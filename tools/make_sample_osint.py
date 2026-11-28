"""Builds js/data/sample-osint.js: the data for the sample case "Harbourline refund scam",
which shows the OSINT side of the app on realistic material — infrastructure pastes, money
on three blockchains, profiles and their earlier versions, a shop page saved twice, post
times for active hours, and the people behind it in the vault. Everything comes from the
test fixtures (made-up names on reserved domains and documentation addresses). The app
loads this file only when it adds the sample case. Run from the repository root."""
import json, csv, io, os, datetime as dt
F = 'tests/fixtures'
rd = lambda p: open(os.path.join(F, p), encoding='utf-8').read()
U = lambda s: int(dt.datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp() * 1000)
R = []
def rec(title, body, ts, source, tags=(), **extra):
    R.append({'title': title, 'body': body, 'ts': U(ts), 'source': source, 'tags': list(tags), **extra})
# infrastructure: what the tools gave back
for f, t, ts in [('whois-portal.txt', 'WHOIS — the refund portal domain', '2026-03-03T09:10:00Z'), ('whois-billing.txt', 'WHOIS — the billing domain', '2026-03-03T09:12:00Z'), ('whois-blog.txt', 'WHOIS — the blog domain', '2026-03-03T09:13:00Z'),
                 ('rdap-invoices.json', 'RDAP — the invoices domain', '2026-03-03T09:15:00Z'), ('dig.txt', 'dig — name servers and mail', '2026-03-03T09:20:00Z'), ('crtsh.json', 'crt.sh — certificates for the portal', '2026-03-03T09:25:00Z'),
                 ('pdns.csv', 'Passive DNS export', '2026-03-03T09:30:00Z'), ('vt-resolutions.json', 'VirusTotal resolutions', '2026-03-03T09:31:00Z'), ('circl.jsonl', 'CIRCL passive DNS', '2026-03-03T09:32:00Z'),
                 ('shodan.json', 'Shodan — the hosting server', '2026-03-03T09:40:00Z'), ('censys.json', 'Censys — the hosting server', '2026-03-03T09:41:00Z')]:
    rec(t, rd('infra/case/' + f), ts, 'paste', ['infrastructure'])
# money: explorer data for the wallets victims paid
for f, t, ts in [('esplora-scam1.json', 'Blockstream — first victim payment and where it went', '2026-03-05T14:00:00Z'), ('blockchain-scam2.json', 'blockchain.com — second victim payment', '2026-03-05T14:05:00Z'),
                 ('blockcypher-peel.json', 'BlockCypher — the peel chain', '2026-03-05T14:10:00Z'), ('etherscan-txlist.json', 'Etherscan — ETH payments', '2026-03-05T14:20:00Z'), ('etherscan-tokentx.json', 'Etherscan — USDT payments', '2026-03-05T14:22:00Z'),
                 ('etherscan-forward.csv', 'Etherscan export — the forwarding wallet', '2026-03-05T14:25:00Z'), ('tronscan-trc20.json', 'Tronscan — USDT on TRON', '2026-03-05T14:30:00Z')]:
    rec(t, rd('chain/' + f), ts, 'paste', ['money'])
# accounts: profile data, some saved twice
for f, t, ts in [('profiles/x-v2-user.json', 'X profile — harbour_deals', '2026-03-01T10:00:00Z'), ('profiles/reddit-old.json', 'Reddit profile — old name', '2026-02-20T10:00:00Z'), ('profiles/reddit-about.json', 'Reddit profile', '2026-03-02T10:00:00Z'),
                 ('profiles/github-kit-before.json', 'GitHub profile — the phishing kit author', '2026-02-26T10:00:00Z'), ('profiles/github-kit-after.json', 'GitHub profile — the kit author, renamed', '2026-03-10T10:00:00Z'),
                 ('profiles/mastodon-account.json', 'Mastodon profile — hlportal', '2026-03-01T12:00:00Z'), ('changes/mastodon-later.json', 'Mastodon profile — hlportal, six weeks later', '2026-04-12T12:00:00Z'), ('profiles/x-profile-page.txt', 'X profile page (copied text)', '2026-03-01T10:05:00Z')]:
    rec(t, rd(f), ts, 'profile', ['profile'])
# victims' reports that name the accounts
rec('Victim report — refund link by DM', 'Victim report: @harbour_deals sent me the refund link by DM on X, asked for my card number and a code from my bank. Paid 0.012 BTC "processing fee" to bc1qqk6ykfsk8wy3rkddzq2m3pm00wnhyha9wegr4q.', '2026-03-04T08:30:00Z', 'victim report', ['victim'])
rec('Victim report — Reddit support account', 'Victim report 2: Reddit user @harbourline_support offered to "speed up the refund" and asked for payment in USDT on TRON. Contact email given: j.harbour@proton.me', '2026-03-04T11:00:00Z', 'victim report', ['victim'])
# the shop page, saved twice (the app reads the HTML as it does a saved page)
PAGES = [{'name': 'about-march.html', 'html': rd('changes/shop-2026-03-01.html'), 'saved': U('2026-03-01T10:00:00Z')}, {'name': 'about-april.html', 'html': rd('changes/shop-2026-04-12.html'), 'saved': U('2026-04-12T09:00:00Z')}]
# post times: who and when only (as the app keeps them)
def compact(posts):
    who, at, t = [], {}, []
    for w, ms in posts:
        if w not in at: at[w] = len(who); who.append(w)
        t.append([at[w], ms])
    return {'who': who, 't': t}
tg = json.loads(rd('hours/telegram-group.json')); ren = {'Dmitri K': '@harbour_deals', 'jake_nyc': 'jake_nyc'}
HOURS = [{'fmt': 'Telegram export', 'title': 'Post times — Telegram group “Night shift”', 'ts': '2026-03-06T10:00:00Z', **compact([(ren.get(m['from'], m['from']), int(m['date_unixtime']) * 1000) for m in tg['messages'] if m.get('type') == 'message'])},
         {'fmt': 'Reddit', 'title': 'Post times — Reddit u/north_wind_77', 'ts': '2026-03-06T10:05:00Z', **compact([('u/' + c['data']['author'], int(c['data']['created_utc'] * 1000)) for c in json.loads(rd('hours/reddit-user.json'))['data']['children']])},
         {'fmt': 'Discord export', 'title': 'Post times — Discord #general', 'ts': '2026-03-06T10:10:00Z', **compact([(m['author']['nickname'], U(m['timestamp'])) for m in json.loads(rd('hours/discord-channel.json'))['messages']])},
         {'fmt': 'CSV', 'title': 'Post times — @newsbot_24', 'ts': '2026-03-06T10:15:00Z', **compact([(r['author'], U(r['timestamp'])) for r in csv.DictReader(io.StringIO(rd('hours/bot.csv')))])}]
A = json.loads(rd('chain/addresses.json'))
# the vault: the person, their identifiers, the wallets; [id, type, fields, tags]
ENTRIES = [['sp-jan', 'person', {'name': 'Jan Harbour', 'dob': '1991-04-02', 'nationality': 'Dutch', 'role': 'Subject'}],
           ['sp-mail', 'email', {'email': 'j.harbour@proton.me', 'provider': 'Proton'}], ['sp-x', 'username', {'username': 'harbour_deals', 'platform': 'X'}], ['sp-rd', 'username', {'username': 'harbourline_support', 'platform': 'Reddit'}],
           ['sp-tel', 'phone', {'number': '+447700900123'}], ['sp-w1', 'crypto', {'address': A['S1'], 'currency': 'Bitcoin'}], ['sp-w2', 'crypto', {'address': A['E1'], 'currency': 'Ethereum'}], ['sp-w3', 'crypto', {'address': A['T1'], 'currency': 'Other'}],
           ['sp-org', 'organization', {'name': 'Harbourline Deals B.V.', 'country': 'Netherlands'}], ['sp-site', 'domain', {'domain': 'harbourline-deals.shop'}]]
LINKS = [['sp-jan', 'sp-mail', 3, 'uses'], ['sp-jan', 'sp-x', 2, 'runs'], ['sp-jan', 'sp-rd', 2, 'runs'], ['sp-jan', 'sp-tel', 3, 'uses'], ['sp-mail', 'sp-w1', 2, 'paid from'], ['sp-jan', 'sp-w2', 2, 'controls'], ['sp-jan', 'sp-w3', 1, 'controls'], ['sp-jan', 'sp-org', 2, 'director of'], ['sp-org', 'sp-site', 3, 'owns']]
# the same person in another sample case, under another name — joined by the email
ELSEWHERE = {'case': 'c-portal', 'entries': [['sp-haven', 'person', {'name': 'J. Haven', 'dob': '1990-04-02', 'nationality': 'Belgian'}], ['sp-mail2', 'email', {'email': 'J.Harbour@proton.me'}]], 'links': [['sp-haven', 'sp-mail2', 3, 'uses']]}
# 1.91: chats, pictures and a document from tests/fixtures/sample (made by tools/make_sample_media.py). The app imports them the way
# it imports your own files — chats through the chat reader, files through the same storage, EXIF and preview steps.
import base64
S = 'tests/fixtures/sample'
rb = lambda n: base64.b64encode(open(os.path.join(S, n), 'rb').read()).decode('ascii')
EXTRA = {
  'chats': [{'name': n, 'text': open(os.path.join(S, n), encoding='utf-8').read()} for n in ('refund-desk.json', 'staff.json', 'dealshub.json')],
  'files': [{'name': 'pier.jpg', 'type': 'image/jpeg', 'b64': rb('pier.jpg'), 'mod': U('2026-03-08T16:44:10Z')},
            {'name': 'warehouse.jpg', 'type': 'image/jpeg', 'b64': rb('warehouse.jpg'), 'mod': U('2026-03-09T08:02:00Z')},
            {'name': 'portal.png', 'type': 'image/png', 'b64': rb('portal.png'), 'mod': U('2026-03-04T10:15:00Z')},
            {'name': 'handbook.docx', 'type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'b64': rb('handbook.docx'), 'mod': U('2026-03-10T07:25:00Z')}],
  # the geolocation of the re-shared picture, as an analyst would have written it in "Where was this taken?"
  'geo': {'file': 'warehouse.jpg', 'data': {
    'note': 'Shared in the staff group the day after "the new desk by the pier" photo, with every piece of metadata stripped by the messenger. Located from the sign and the building, then matched to the pier photo’s GPS, about 300 m away.',
    'clues': [{'id': 'c1', 'kind': 'sign', 'text': 'Sign: "SADAMA — LADU 7 · PEALEVÕTT" (harbour, warehouse 7, pick-up)'},
              {'id': 'c2', 'kind': 'lang', 'text': 'Estonian: õ in PEALEVÕTT; "sadama" and "ladu" are Estonian words'},
              {'id': 'c3', 'kind': 'build', 'text': 'Red-brick port warehouse with tall loading doors'},
              {'id': 'c4', 'kind': 'sky', 'text': 'Shadow falls to the north-east: sun in the south-west, afternoon'},
              {'id': 'c5', 'kind': 'road', 'text': 'Dashed white centre line, no kerb: a port service road'}],
    'cands': [{'id': 'k1', 'name': 'Sadama street by the old port, Tallinn', 'lat': 59.44410, 'lon': 24.76120, 'verdict': 'confirmed', 'fit': {'c1': 'y', 'c2': 'y', 'c3': 'y', 'c4': 'y', 'c5': 'y'},
               'note': 'Brick warehouses on the port side of Sadama street; about 300 m from the GPS in pier.jpg, taken the evening before.'},
              {'id': 'k2', 'name': 'Sadama, Pärnu', 'lat': 58.38300, 'lon': 24.49700, 'verdict': 'out', 'fit': {'c1': 'y', 'c2': 'y', 'c3': 'n'}, 'note': 'Also a Sadama street, but no brick warehouses on it.'},
              {'id': 'k3', 'name': 'Rotterdam — the address the company gives', 'lat': 51.92250, 'lon': 4.47920, 'verdict': 'out', 'fit': {'c1': 'n', 'c2': 'n'}, 'note': 'Dutch signage would not be in Estonian.'}]}},
  'entries': [['sp-desk', 'location', {'address': 'Sadama street, Tallinn old port', 'city': 'Tallinn', 'country': 'Estonia', 'coordinates': '59.44410, 24.76120'}],
              ['sp-mira', 'person', {'name': 'Mira S', 'role': 'Refund desk staff (Telegram)'}],
              ['sp-tgdk', 'username', {'username': 'Dmitri K', 'platform': 'Telegram'}],
              ['sp-chan', 'url', {'url': 'https://t.me/harbour_payouts'}]],
  'links': [['sp-org', 'sp-desk', 2, 'works from (photo GPS, geolocation)'], ['sp-jan', 'sp-tgdk', 1, 'possibly the same as'], ['sp-mira', 'sp-tgdk', 2, 'works for'], ['sp-tgdk', 'sp-chan', 2, 'pays staff through']],
}
out = {'case': {'id': 'c-harbour', 'code': 'HL-2026-031', 'name': 'Harbourline refund scam', 'scope': 'Fake refund support on X, Reddit and Telegram after a marine-electronics shop went quiet: who runs it, where the money goes, and when they work.', 'color': '#0ea5e9', 'icon': 'briefcase', 'created': U('2026-03-01T09:00:00Z')},
       'records': R, 'pages': PAGES, 'hours': HOURS, 'entries': ENTRIES, 'links': LINKS, 'elsewhere': ELSEWHERE, 'extra': EXTRA}
s = json.dumps(out, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/')   # so the file can sit inside a <script> in the offline build
open('js/data/sample-osint.js', 'w').write('/* Sample case “Harbourline refund scam” — built by tools/make_sample_osint.py from the test fixtures; loaded only when the sample case is added. */\nconst SAMPLE_OSINT = ' + s + ';\n')
print(len(s), 'bytes;', len(R), 'records;', sum(len(h['t']) for h in HOURS), 'post times')
