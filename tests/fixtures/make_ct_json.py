"""A fictional crt.sh JSON export (what https://crt.sh/?q=%25.northwind-traders.example&output=json returns)
for the Certificate Transparency view. The domain is under the reserved .example TLD; nothing here is real."""
import json, os, random, datetime as dt
random.seed(7)
D = 'northwind-traders.example'
ISS = [(1, "C=US, O=Let's Encrypt, CN=R11", 90, 0.55), (2, "C=US, O=Let's Encrypt, CN=E5", 90, 0.15), (3, 'C=GB, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA', 365, 0.2), (4, 'C=US, O=Example Trust Services, CN=Example Issuing CA R1', 395, 0.1)]
steady = ['www', '', 'mail', 'autodiscover', 'vpn', 'sso', 'api', 'shop', 'cdn', 'owa', 'remote', 'portal']
later = [('dev', 2024), ('staging', 2024), ('jenkins', 2024), ('gitlab', 2025), ('grafana', 2025), ('test-legacy', 2023), ('citrix', 2023), ('backup-01', 2025), ('admin-panel', 2026)]
out, i = [], 1000
start = dt.datetime(2023, 1, 10)
for m in range(46):
    day = start + dt.timedelta(days=30 * m)
    for k in range(random.choice([1, 2, 2, 3])):
        iid, iname, life, _ = random.choices(ISS, weights=[x[3] for x in ISS])[0]
        nb = day + dt.timedelta(days=random.randint(0, 25), hours=random.randint(0, 23), minutes=random.randint(0, 59))
        if iid in (3, 4): names = [D, 'www.' + D, '*.' + D] if random.random() < .5 else [D, 'www.' + D]
        else:
            pool = [s for s in steady] + [s for s, y in later if nb.year >= y]
            names = sorted({(s + '.' if s else '') + D for s in random.sample(pool, random.randint(1, 4))})
        if day.year == 2026 and day.month >= 8 and k == 0: names = sorted(set(names) | {'admin-panel.' + D, 'login-' + D.replace('.example', '') + '.' + D})
        serial = '%032x' % random.getrandbits(128)
        for pre in (True, False):            # crt.sh lists the precertificate and the certificate separately
            i += 1
            out.append({'issuer_ca_id': iid, 'issuer_name': iname, 'common_name': names[0], 'name_value': '\n'.join(names), 'id': 9000000000 + i,
                        'entry_timestamp': (nb + dt.timedelta(minutes=1 if pre else 4)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3],
                        'not_before': nb.strftime('%Y-%m-%dT%H:%M:%S'), 'not_after': (nb + dt.timedelta(days=life)).strftime('%Y-%m-%dT%H:%M:%S'), 'serial_number': serial, 'result_count': 2 if pre else 3})
out.sort(key=lambda x: -x['id'])
json.dump(out, open(os.path.join(os.path.dirname(__file__), 'crtsh-northwind.json'), 'w'), indent=0)
print(len(out), 'entries')
