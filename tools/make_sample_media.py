"""Writes tests/fixtures/sample/: the chats, pictures and the Word document that Op Lantern's sample shows (1.91).
Everything is invented: people, handles, account numbers and wallets are made up or come from the other test fixtures;
domains are reserved (.test, .example) and addresses are documentation ranges. The places are public streets by a port.

    python tools/make_sample_media.py      (needs Pillow; run tools/make_sample_osint.py after it)

  refund-desk.json   Telegram Desktop export of a public channel: the scam's "refund desk"
  staff.json         Telegram Desktop export of the staff group: forwards from the channel, a renamed member, the server
                     from the intrusion, payout wallets
  dealshub.json      DiscordChatExporter JSON: the same refund post pushed by two accounts within minutes
  pier.jpg           a photo with camera, time and GPS (Tallinn's old port) — not where the company says it is
  warehouse.jpg      the same area, re-shared through a messenger: no metadata left, so it is geolocated by hand
  portal.png         a screenshot of the refund portal
  handbook.docx      the staff handbook: tracked changes, a comment, hidden text and the author's account
"""
import json, io, os, zipfile, datetime as dt
from PIL import Image, ImageDraw, ImageFont

OUT = os.path.join('tests', 'fixtures', 'sample')
os.makedirs(OUT, exist_ok=True)
A = json.load(open(os.path.join('tests', 'fixtures', 'chain', 'addresses.json'), encoding='utf-8'))
UTC = dt.timezone.utc
def ts(s): return int(dt.datetime.fromisoformat(s).replace(tzinfo=UTC).timestamp())
def iso_local(s, hours=2): return (dt.datetime.fromisoformat(s) + dt.timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%S')
def save_json(name, obj): open(os.path.join(OUT, name), 'w', encoding='utf-8', newline='\n').write(json.dumps(obj, ensure_ascii=False, indent=1) + '\n')

# ---------------------------------------------------------------- Telegram: the public channel
CH_ID, CH = 1777000001, 'Harbourline Refund Desk'
POSTS = [
  ('2026-03-02T07:05:00', 'Harbourline customers: orders cancelled after the warehouse move are being refunded. Open harbour-line-portal.test/refund with your order number to claim.'),
  ('2026-03-02T15:40:00', 'Refunds are paid within 24 hours once your card is verified. Support never asks for your password, only the confirmation code.'),
  ('2026-03-03T07:10:00', 'Queue is long today. If the portal is slow, write to @harbourline_support on Reddit or to j.harbour@proton.me and we process it by hand.'),
  ('2026-03-04T06:55:00', 'New refund link for orders 4400 to 4800: harbour-line-portal.test/r/4400. The old link stops working tonight.'),
  ('2026-03-05T08:20:00', 'A small processing fee is taken in crypto for international refunds. Pay only to the address shown in the portal.'),
  ('2026-03-06T07:00:00', 'Thank you for your patience. 312 refunds paid this week. Claim yours before Friday: harbour-line-portal.test/refund'),
  ('2026-03-08T09:30:00', 'Weekend team is on. Write to us with your order number and the last four digits of your card.'),
  ('2026-03-10T07:15:00', 'Portal moved to a faster server today. If the page does not open, clear your browser and try again.'),
  ('2026-03-12T07:05:00', 'Last week to claim refunds for cancelled orders. After 20 March unclaimed refunds go back to the bank.'),
]
save_json('refund-desk.json', {'name': CH, 'type': 'public_channel', 'id': CH_ID, 'messages': [
  {'id': i + 1, 'type': 'message', 'date': iso_local(t), 'date_unixtime': str(ts(t)), 'from': CH, 'from_id': f'channel{CH_ID}', 'text': x} for i, (t, x) in enumerate(POSTS)]})

# ---------------------------------------------------------------- Telegram: the staff group
DM, LAMP, MIRA = ('Dmitri K', 'user101'), ('n1ghtlamp', 'user303'), ('Mira S', 'user404')
STAFF = []
def say(t, who, text, fwd=None): STAFF.append((t, who, text, fwd))
say('2026-03-01T18:02:00', DM, 'Group for the desk. Channel goes live tomorrow morning, portal is ready on the usual box.')
say('2026-03-01T18:10:00', LAMP, 'portal is on 198.51.100.23 same as before, update-lamp.test still points there too, dont worry about it')
say('2026-03-01T18:12:00', DM, 'Move it before the week is out. I do not want the two things on one address.')
say('2026-03-02T07:06:00', DM, POSTS[0][1], CH)
say('2026-03-02T09:30:00', MIRA, 'First three claims in. All three paid the fee. Which wallet do I give for BTC?')
say('2026-03-02T09:34:00', DM, f'BTC to {A["S1"]} only. USDT on TRON to {A["T1"]}. Nothing else.')
say('2026-03-02T15:41:00', DM, POSTS[1][1], CH)
say('2026-03-03T08:15:00', MIRA, 'Someone asked who owns the company. I said Harbourline Deals B.V., Rotterdam, like the site says.')
say('2026-03-03T08:20:00', DM, 'Good. Never say Tallinn. The office stays out of everything.')
say('2026-03-04T06:56:00', DM, POSTS[3][1], CH)
say('2026-03-04T12:40:00', LAMP, 'new batch of numbers from the shop database is in the drive, 1900 rows')
say('2026-03-05T08:21:00', DM, POSTS[4][1], CH)
say('2026-03-05T10:05:00', MIRA, 'Fee payments today: 14 BTC, 9 USDT. Sending the list tonight.')
say('2026-03-06T07:01:00', DM, POSTS[5][1], CH)
say('2026-03-07T19:30:00', ('lamp', 'user303'), 'changed my name here, the old one is on too many forums now')
say('2026-03-08T09:31:00', DM, POSTS[6][1], CH)
say('2026-03-08T16:45:00', MIRA, 'Photo of the new desk by the pier, the view is nice at least')
say('2026-03-10T07:16:00', DM, POSTS[7][1], CH)
say('2026-03-10T07:30:00', ('lamp', 'user303'), 'moved the portal off the old box as you asked. dns will catch up in a day')
say('2026-03-10T11:02:00', MIRA, 'Payouts channel for the team: t.me/harbour_payouts')
say('2026-03-12T07:06:00', DM, POSTS[8][1], CH)
say('2026-03-12T21:10:00', DM, 'After the 20th we close the desk, wipe the group and start the next shop.')
save_json('staff.json', {'name': 'HL desk staff', 'type': 'private_supergroup', 'id': 1777000002, 'messages': [
  {'id': i + 1, 'type': 'message', 'date': iso_local(t), 'date_unixtime': str(ts(t)), 'from': who[0], 'from_id': who[1], 'text': text,
   **({'forwarded_from': fwd, 'forwarded_from_id': f'channel{CH_ID}'} if fwd else {})} for i, (t, who, text, fwd) in enumerate(STAFF)]})

# ---------------------------------------------------------------- Discord: the coordinated push
def snowflake(iso, seq=0): return str(((int(dt.datetime.fromisoformat(iso).replace(tzinfo=UTC).timestamp() * 1000) - 1420070400000) << 22) + seq)
SUP = {'id': snowflake('2026-02-24T10:00:00', 1), 'name': 'harbourline_support', 'nickname': 'Harbourline Support'}
QF = {'id': snowflake('2026-02-25T22:15:00', 2), 'name': 'quickfix_88', 'nickname': 'quickfix'}
MEMBERS = [{'id': snowflake('2021-06-01T12:00:00', 3), 'name': 'sailnut', 'nickname': 'sailnut'}, {'id': snowflake('2019-11-11T09:00:00', 4), 'name': 'marta.k', 'nickname': 'Marta'}]
DISC = [
  ('2026-03-02T07:20:00', MEMBERS[0], 'anyone else had their Harbourline order cancelled? no reply from the shop for 3 weeks'),
  ('2026-03-02T07:31:00', SUP, POSTS[0][1]),
  ('2026-03-02T07:34:00', QF, POSTS[0][1]),
  ('2026-03-02T08:02:00', MEMBERS[1], 'is that link real? the shop site never mentioned a refund portal'),
  ('2026-03-02T08:05:00', QF, 'it is real, I got mine yesterday, took 10 minutes'),
  ('2026-03-04T07:01:00', SUP, POSTS[3][1]),
  ('2026-03-04T07:03:00', QF, POSTS[3][1]),
  ('2026-03-05T12:44:00', MEMBERS[1], 'they asked me for a fee in bitcoin before paying the refund. reporting this to the bank'),
  ('2026-03-05T12:50:00', SUP, 'Please send us a direct message, we will look at your case personally.'),
]
save_json('dealshub.json', {'guild': {'id': snowflake('2020-03-01T00:00:00', 9), 'name': 'Deals Hub'}, 'channel': {'id': snowflake('2020-03-01T00:01:00', 10), 'type': 'GuildTextChat', 'name': 'refunds'},
  'messages': [{'id': snowflake(t, i), 'type': 'Default', 'timestamp': t + '+00:00', 'content': c, 'author': a} for i, (t, a, c) in enumerate(DISC)]})

# ---------------------------------------------------------------- pictures
def font(size):
  for f in ['/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', '/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf']:
    if os.path.exists(f): return ImageFont.truetype(f, size)
  return ImageFont.load_default()
def sky(d, w, h, top, bottom):
  for y in range(h):
    k = y / max(1, h - 1); d.line([(0, y), (w, y)], fill=tuple(int(top[i] + (bottom[i] - top[i]) * k) for i in range(3)))

def pier():
  w, h = 1280, 853; im = Image.new('RGB', (w, h)); d = ImageDraw.Draw(im)
  sky(d, w, 470, (52, 74, 112), (236, 170, 120))
  d.ellipse([930, 330, 1010, 410], fill=(250, 214, 160))                                         # low sun in the south-west
  for y in range(470, h):                                                                         # the sea
    k = (y - 470) / (h - 470); d.line([(0, y), (w, y)], fill=(int(40 + 30 * (1 - k)), int(62 + 30 * (1 - k)), int(88 + 30 * (1 - k))))
  for i in range(0, w, 37): d.line([(i, 520 + (i * 7) % 40), (i + 18, 520 + (i * 7) % 40)], fill=(225, 170, 120), width=2)
  d.polygon([(0, 600), (760, 548), (760, 566), (0, 640)], fill=(62, 56, 52))                       # the pier
  for x in range(40, 760, 70): d.rectangle([x, 560 - x // 16, x + 6, 600 - x // 22], fill=(38, 34, 32))
  d.polygon([(780, 470), (1180, 470), (1150, 505), (805, 505)], fill=(236, 236, 232))              # a ferry on the horizon
  d.rectangle([850, 440, 1080, 470], fill=(230, 230, 226)); d.rectangle([905, 418, 1010, 440], fill=(214, 70, 60))
  for x in range(865, 1075, 22): d.rectangle([x, 448, x + 12, 458], fill=(70, 90, 120))
  d.rectangle([120, 380, 400, 450], fill=(28, 84, 130)); d.rectangle([254, 450, 266, 560], fill=(60, 60, 60))   # a terminal sign
  d.text((140, 395), 'TERMINAL D', font=font(34), fill=(255, 255, 255))
  return im

def warehouse():
  w, h = 1080, 1080; im = Image.new('RGB', (w, h)); d = ImageDraw.Draw(im)
  sky(d, w, 330, (150, 186, 220), (214, 228, 238))
  d.rectangle([0, 230, w, 860], fill=(150, 72, 54))                                                # red brick
  for y in range(240, 860, 26):
    off = 0 if (y // 26) % 2 else 30
    for x in range(-60 + off, w, 60): d.rectangle([x, y, x + 56, y + 22], outline=(124, 58, 44))
  for x in (90, 380, 670): d.rectangle([x, 470, x + 220, 760], fill=(58, 64, 70)); d.rectangle([x + 10, 480, x + 210, 750], outline=(90, 96, 102), width=4)
  d.rectangle([300, 300, 780, 420], fill=(16, 72, 140))                                            # the sign
  d.text((340, 315), 'SADAMA', font=font(52), fill=(255, 255, 255)); d.text((340, 372), 'LADU 7  ·  PEALEVÕTT', font=font(30), fill=(220, 232, 255))
  d.rectangle([0, 860, w, h], fill=(80, 82, 86))                                                   # the road
  for x in range(0, w, 160): d.rectangle([x, 960, x + 90, 976], fill=(240, 240, 240))
  d.polygon([(0, 860), (240, 860), (420, h), (0, h)], fill=(64, 66, 70))                           # a shadow falling to the north-east
  return im

def portal():
  w, h = 1280, 800; im = Image.new('RGB', (w, h), (243, 245, 248)); d = ImageDraw.Draw(im)
  d.rectangle([0, 0, w, 56], fill=(226, 230, 236)); d.rounded_rectangle([140, 12, 1100, 44], 16, fill=(255, 255, 255))
  d.text((160, 18), 'harbour-line-portal.test/refund', font=font(20), fill=(60, 66, 80))
  d.rectangle([0, 56, w, 140], fill=(12, 64, 120)); d.text((80, 82), 'Harbourline Deals — Refund centre', font=font(32), fill=(255, 255, 255))
  d.rounded_rectangle([360, 190, 920, 700], 14, fill=(255, 255, 255), outline=(220, 224, 230))
  d.text((400, 220), 'Claim your refund', font=font(30), fill=(20, 24, 32))
  for i, lab in enumerate(['Order number', 'Name on card', 'Card number', 'Confirmation code from your bank']):
    y = 290 + i * 88; d.text((400, y), lab, font=font(18), fill=(70, 76, 90)); d.rounded_rectangle([400, y + 26, 880, y + 66], 8, outline=(200, 206, 214), fill=(250, 251, 252))
  d.rounded_rectangle([400, 640, 880, 684], 10, fill=(14, 116, 72)); d.text((560, 650), 'Get my refund', font=font(22), fill=(255, 255, 255))
  return im

def jpeg(im, name, exif=None):
  b = io.BytesIO(); im.save(b, 'JPEG', quality=86, **({'exif': exif} if exif is not None else {})); open(os.path.join(OUT, name), 'wb').write(b.getvalue())
def dms(v): v = abs(v); d = int(v); m = int((v - d) * 60); s = round(((v - d) * 60 - m) * 60, 2); return (float(d), float(m), float(s))

ex = Image.Exif()
ex[0x010F], ex[0x0110], ex[0x0131], ex[0x0132] = 'Google', 'Pixel 7', 'HDR+ 1.0.540104767zd', '2026:03:08 18:44:10'
sub = ex.get_ifd(0x8769); sub[0x9003] = '2026:03:08 18:44:10'; sub[0x9004] = '2026:03:08 18:44:10'; sub[0x9011] = '+02:00'; sub[0x920A] = 6.81
gps = ex.get_ifd(0x8825); LAT, LON = 59.444720, 24.766030
gps[1], gps[2], gps[3], gps[4] = 'N', dms(LAT), 'E', dms(LON); gps[5], gps[6] = 0, 4.0; gps[17] = 231.0; gps[16] = 'T'
jpeg(pier(), 'pier.jpg', ex)
jpeg(warehouse(), 'warehouse.jpg')            # re-shared through a messenger: no metadata at all
b = io.BytesIO(); portal().save(b, 'PNG', optimize=True); open(os.path.join(OUT, 'portal.png'), 'wb').write(b.getvalue())

# ---------------------------------------------------------------- the Word document
W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml"'
def p(*runs): return '<w:p>' + ''.join(runs) + '</w:p>'
def r(t): return f'<w:r><w:t xml:space="preserve">{t}</w:t></w:r>'
REV = iter(range(101, 200))
def ins(t, who, at): return f'<w:ins w:id="{next(REV)}" w:author="{who}" w:date="{at}"><w:r><w:t xml:space="preserve">{t}</w:t></w:r></w:ins>'
def dele(t, who, at): return f'<w:del w:id="{next(REV)}" w:author="{who}" w:date="{at}"><w:r><w:delText xml:space="preserve">{t}</w:delText></w:r></w:del>'
def hidden(t): return f'<w:r><w:rPr><w:vanish/></w:rPr><w:t xml:space="preserve">{t}</w:t></w:r>'
def commented(t, cid): return f'<w:commentRangeStart w:id="{cid}"/>{r(t)}<w:commentRangeEnd w:id="{cid}"/><w:r><w:commentReference w:id="{cid}"/></w:r>'
body = ''.join([
  p(r('Refund desk — handbook for new staff')),
  p(r('1. Answer customers within ten minutes. Always use the name of the shop, never your own.')),
  p(r('2. Send every customer to the portal. '), ins('If the portal is down, take the order number by message and pass it to the desk lead.', 'Dmitri K', '2026-03-01T17:40:00Z')),
  p(r('3. Fees: '), dele(f'payouts go to {A["S1"]} (BTC) and {A["T1"]} (USDT on TRON). ', 'Jan Harbour', '2026-03-02T08:15:00Z'), commented('ask the desk lead which address to give.', 0)),
  p(r('4. The company is Harbourline Deals B.V., Rotterdam. '), hidden('Desk: Sadama, Tallinn old port — never mention it.')),
  p(r('5. The group and this file are deleted when the desk closes.')),
])
DOC = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {W}><w:body>{body}<w:sectPr/></w:body></w:document>'
COMMENTS = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:comments {W}><w:comment w:id="0" w:author="Jan Harbour" w:initials="JH" w:date="2026-03-02T08:16:00Z">{p(r("Take the wallets out before this goes to the new people."))}</w:comment></w:comments>'
PEOPLE = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w15:people {W}><w15:person w15:author="Jan Harbour"><w15:presenceInfo w15:providerId="Windows Live" w15:userId="j.harbour@proton.me"/></w15:person><w15:person w15:author="Dmitri K"><w15:presenceInfo w15:providerId="None" w15:userId="Dmitri K"/></w15:person></w15:people>'
SETTINGS = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:settings {W}><w:trackRevisions/><w:rsids><w:rsidRoot w:val="00A1B2C3"/><w:rsid w:val="00A1B2C3"/><w:rsid w:val="00D4E5F6"/><w:rsid w:val="00F7A8B9"/></w:rsids></w:settings>'
CORE = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Refund desk handbook</dc:title><dc:creator>Jan Harbour</dc:creator><cp:lastModifiedBy>lamp</cp:lastModifiedBy>'
        '<cp:revision>7</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">2026-02-27T16:05:00Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2026-03-10T07:25:00Z</dcterms:modified></cp:coreProperties>')
APP = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Microsoft Office Word</Application>'
       '<AppVersion>16.0000</AppVersion><Company>Harbourline Deals B.V.</Company><TotalTime>94</TotalTime></Properties>')
CUSTOM = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
          '<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="Desk"><vt:lpwstr>Tallinn</vt:lpwstr></property></Properties>')
CT = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
      '<Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
      '<Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/><Override PartName="/word/people.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.people+xml"/>'
      '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
      '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/><Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/></Types>')
RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
        '<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/></Relationships>')
DRELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>'
         '<Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2011/relationships/people" Target="people.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/></Relationships>')
b = io.BytesIO()
with zipfile.ZipFile(b, 'w', zipfile.ZIP_DEFLATED) as z:
  for name, data in [('[Content_Types].xml', CT), ('_rels/.rels', RELS), ('word/document.xml', DOC), ('word/_rels/document.xml.rels', DRELS), ('word/comments.xml', COMMENTS),
                     ('word/people.xml', PEOPLE), ('word/settings.xml', SETTINGS), ('docProps/core.xml', CORE), ('docProps/app.xml', APP), ('docProps/custom.xml', CUSTOM)]:
    zi = zipfile.ZipInfo(name, (2026, 3, 10, 7, 25, 0)); zi.compress_type = zipfile.ZIP_DEFLATED; z.writestr(zi, data)
open(os.path.join(OUT, 'handbook.docx'), 'wb').write(b.getvalue())
print('wrote', ', '.join(sorted(os.listdir(OUT))))
