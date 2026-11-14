"""Builds js/data/attack.js (MITRE ATT&CK Enterprise, compacted) and js/data/kev-snapshot.js (CISA KEV).
Run from the project root: python3 tools/make_intel_data.py   (downloads both from GitHub)"""
import json, re, os, sys, urllib.request
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'js', 'data')
def get(url, local):
    if os.path.exists(local): return json.load(open(local, encoding='utf-8'))
    with urllib.request.urlopen(url, timeout=180) as r: return json.loads(r.read().decode('utf-8'))
EA = get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json', 'ea.json')
ea = EA['objects']
live = lambda o: not o.get('revoked') and not o.get('x_mitre_deprecated')
ext = lambda o: next((r['external_id'] for r in o.get('external_references', []) if r.get('source_name') == 'mitre-attack'), None)
def first(desc, n=260):
    d = re.sub(r'\(Citation:[^)]*\)', '', desc or '')
    d = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', d)
    d = re.sub(r'<[^>]+>', '', d).replace('\n', ' ').strip()
    m = re.match(r'(.{40,}?[.!?])\s', d + ' ')
    s = m.group(1) if m else d
    return (s[:n-1] + '…') if len(s) > n else s
matrix = next(o for o in ea if o['type'] == 'x-mitre-matrix')
tacts = {o['id']: o for o in ea if o['type'] == 'x-mitre-tactic'}
tactics = [[ext(tacts[t]), tacts[t]['x_mitre_shortname'], tacts[t]['name']] for t in matrix['tactic_refs']]
byid = {o['id']: o for o in ea}
techs = []
for o in ea:
    if o['type'] == 'attack-pattern' and live(o) and ext(o):
        techs.append([ext(o), o['name'], [p['phase_name'] for p in o.get('kill_chain_phases', []) if p.get('kill_chain_name') == 'mitre-attack']])
techs.sort(key=lambda t: t[0])
uses = {}
for r in ea:
    if r['type'] == 'relationship' and r.get('relationship_type') == 'uses' and live(r):
        uses.setdefault(r['source_ref'], set()).add(r['target_ref'])
def refs(oid, typ):
    return sorted({ext(byid[t]) for t in uses.get(oid, ()) if t in byid and byid[t]['type'] in typ and live(byid[t]) and ext(byid[t])})
groups = []
for o in ea:
    if o['type'] == 'intrusion-set' and live(o) and ext(o):
        al = [a for a in o.get('aliases', []) if a != o['name']]
        groups.append({'id': ext(o), 'n': o['name'], 'a': al, 'd': first(o.get('description')), 't': refs(o['id'], ('attack-pattern',)), 's': refs(o['id'], ('malware', 'tool'))})
soft = []
for o in ea:
    if o['type'] in ('malware', 'tool') and live(o) and ext(o):
        al = [a for a in o.get('x_mitre_aliases', []) if a != o['name']]
        soft.append({'id': ext(o), 'n': o['name'], 'a': al, 'k': 'm' if o['type'] == 'malware' else 't', 'd': first(o.get('description'), 200)})
groups.sort(key=lambda g: g['n'].lower()); soft.sort(key=lambda g: g['n'].lower())
ver = matrix.get('x_mitre_version') or ''
coll = {'x_mitre_version': 'Enterprise ' + matrix.get('modified', '')[:10]}
js = ('/* MITRE ATT&CK® Enterprise, compacted for offline use: tactics, techniques, groups and software.\n'
      '   Source: github.com/mitre/cti (enterprise-attack). © The MITRE Corporation, used under the ATT&CK terms of use.\n'
      '   ATT&CK ' + coll['x_mitre_version'] + '. Regenerate: python3 tools/make_intel_data.py */\n'
      'const ATTACK = ' + json.dumps({'v': coll.get('x_mitre_version', ''), 'tactics': tactics, 'tech': techs, 'groups': groups, 'soft': soft}, separators=(',', ':'), ensure_ascii=False) + ';\n')
open(os.path.join(ROOT, 'attack.js'), 'w', encoding='utf-8', newline='\n').write(js)
k = get('https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json', 'kev.json')
rows = []
for v in k['vulnerabilities']:
    d = (v.get('shortDescription') or '').strip()
    rows.append([v['cveID'], v.get('vendorProject', ''), v.get('product', ''), v.get('vulnerabilityName', ''), v.get('dateAdded', ''), v.get('dueDate', ''), 1 if v.get('knownRansomwareCampaignUse') == 'Known' else 0, (d[:219] + '…') if len(d) > 220 else d, ','.join(v.get('cwes', []) or [])])
js2 = ('/* CISA Known Exploited Vulnerabilities catalog, snapshot for offline use (public domain, U.S. Government work).\n'
       '   Source: github.com/cisagov/kev-data. Catalog ' + k['catalogVersion'] + ', ' + str(k['count']) + ' entries. Refresh it live from Threat Intel → Sources. */\n'
       'const KEV_SNAPSHOT = ' + json.dumps({'v': k['catalogVersion'], 'at': k['dateReleased'], 'rows': rows}, separators=(',', ':'), ensure_ascii=False) + ';\n')
open(os.path.join(ROOT, 'kev-snapshot.js'), 'w', encoding='utf-8', newline='\n').write(js2)
print(len(tactics), len(techs), len(groups), len(soft), len(rows), coll.get('x_mitre_version'))
