#!/usr/bin/env python3
"""Writes the three forensic files of the sample case "Harbourline refund scam" into tests/fixtures/sample:

    lind-chrome-profile.zip      a victim's Chrome profile (History, Shortcuts, Web Data, Login Data, Preferences, Bookmarks)
    office-pc2-security.evtx     the Security log of the real shop's office PC: a password spray, then a remote desktop session
    shop-cloudtrail.json         CloudTrail from the real shop's AWS account: its backup key used from the portal's server

The story: the scammers pose as the refund desk of a marine-electronics shop that went quiet. Its customer list was
taken from the shop itself — through the office PC, then the cloud bucket the PC backs up to — from 198.51.100.23,
the address the staff chat names as the portal's server. A customer who paid the "fee" handed over her browser profile.

Everything is made up: domains end in .test or .example, addresses are documentation ranges and the people do not exist.
The output is the same on every run.  Run:  python3 tools/make_sample_forensics.py   (standard library only)
"""
import datetime as dt, importlib.util, io, json, os, sqlite3, tempfile, zipfile

OUT = os.path.join('tests', 'fixtures', 'sample')
UTC = dt.timezone.utc
def unix(s): return int(dt.datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp())
def webkit(s): return (unix(s) + 11644473600) * 1_000_000          # Chrome: microseconds since 1601

PORTAL, NEWBOX, OFFICE = '198.51.100.23', '203.0.113.80', '192.0.2.44'

# ---------------------------------------------------------------- the victim's Chrome profile
VISITS = [  # time (UTC), url, title, transition core (0 link, 1 typed, 5 generated, 7 form)
  ('2026-03-04T17:02:10Z', 'https://www.google.com/search?q=harbourline+refund+cancelled+order', 'harbourline refund cancelled order - Google Search', 5),
  ('2026-03-04T17:02:41Z', 'https://www.reddit.com/r/boating/comments/1b7x2q/harbourline_orders_cancelled/', 'Harbourline orders cancelled? : r/boating', 0),
  ('2026-03-04T17:03:30Z', 'https://www.reddit.com/user/harbourline_support/', 'harbourline_support (u/harbourline_support) - Reddit', 0),
  ('2026-03-04T17:04:02Z', 'https://harbour-line-portal.test/r/4400', 'Harbourline — Refund claim', 0),
  ('2026-03-04T17:05:48Z', 'https://harbour-line-portal.test/r/4400/claim', 'Harbourline — Your order', 7),
  ('2026-03-04T17:06:30Z', 'https://harbour-line-portal.test/r/4400/verify', 'Harbourline — Verify your card', 7),
  ('2026-03-04T17:07:15Z', 'https://harbour-line-portal.test/r/4400/fee', 'Harbourline — International refund fee', 7),
  ('2026-03-04T17:09:02Z', 'https://www.google.com/search?q=how+to+buy+bitcoin+quickly', 'how to buy bitcoin quickly - Google Search', 5),
  ('2026-03-04T17:10:20Z', 'https://coins-now.example/buy', 'Buy Bitcoin in minutes — CoinsNow', 0),
  ('2026-03-04T17:31:44Z', 'https://coins-now.example/send', 'Send — CoinsNow', 0),
  ('2026-03-04T17:33:05Z', 'https://harbour-line-portal.test/r/4400/fee/paid', 'Harbourline — Payment received', 0),
  ('2026-03-04T17:33:40Z', 'https://harbour-line-portal.test/r/4400/receipt', 'Harbourline — Your refund receipt', 0),
  ('2026-03-06T07:48:12Z', 'https://harbour-line-portal.test/r/4400/status', 'Harbourline — Refund status: processing', 1),
  ('2026-03-07T18:20:33Z', 'https://www.google.com/search?q=harbourline+refund+scam', 'harbourline refund scam - Google Search', 5),
  ('2026-03-07T18:21:10Z', 'https://www.reddit.com/r/Scams/comments/1b9k4d/harbourline_refund_desk_telegram/', 'Harbourline "refund desk" on Telegram? : r/Scams', 0),
  ('2026-03-07T18:24:51Z', 'https://harbourline-marine.example/', 'Harbourline Marine — marine electronics', 1),
  ('2026-03-07T18:25:30Z', 'https://harbourline-marine.example/notice', 'Notice to customers — Harbourline Marine', 0),
]
SEARCHES = {0: 'harbourline refund cancelled order', 7: 'how to buy bitcoin quickly', 13: 'harbourline refund scam'}
TYPED = [('harbour-line-portal.test/r/4400/status', VISITS[12], 2), ('harbourline-marine.example', VISITS[15], 1)]
FORM = [  # field, value, count, first, last
  ('order_number', '4471', 2, '2026-03-04T17:05:40Z', '2026-03-06T07:48:30Z'),
  ('email', 'p.lind@example.net', 3, '2026-03-04T17:05:44Z', '2026-03-06T07:48:31Z'),
  ('card_holder', 'PETRA LIND', 1, '2026-03-04T17:06:20Z', '2026-03-04T17:06:20Z'),
  ('confirmation_code', '804613', 1, '2026-03-04T17:06:58Z', '2026-03-04T17:06:58Z'),   # the code her bank texted her: shown masked
  ('wallet_from', 'CoinsNow', 1, '2026-03-04T17:31:30Z', '2026-03-04T17:31:30Z'),
]

def sqlite_bytes(sql):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 'db'); c = sqlite3.connect(p); c.executescript(sql); c.commit(); c.execute('VACUUM'); c.close()
        return open(p, 'rb').read()

def q(v): return "'" + str(v).replace("'", "''") + "'"

def history():
    urls, seen = [], {}
    for t, u, title, _ in VISITS:
        if u not in seen: seen[u] = len(urls) + 1; urls.append([seen[u], u, title, 0, 0, 0])
        R = urls[seen[u] - 1]; R[3] += 1; R[5] = webkit(t)
    for text, v, n in TYPED: urls[seen[v[1]] - 1][4] += n
    s = ['CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);',
         'CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER, transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER, visit_duration INTEGER DEFAULT 0 NOT NULL);',
         'CREATE TABLE keyword_search_terms(keyword_id INTEGER NOT NULL, url_id INTEGER NOT NULL, term LONGVARCHAR NOT NULL, normalized_term LONGVARCHAR NOT NULL);',
         'CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL, current_path LONGVARCHAR NOT NULL, target_path LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL, total_bytes INTEGER NOT NULL, state INTEGER NOT NULL, danger_type INTEGER NOT NULL, interrupt_reason INTEGER NOT NULL, hash BLOB NOT NULL, end_time INTEGER NOT NULL, opened INTEGER NOT NULL, last_access_time INTEGER NOT NULL, transient INTEGER NOT NULL, referrer VARCHAR NOT NULL, site_url VARCHAR NOT NULL, tab_url VARCHAR NOT NULL, tab_referrer_url VARCHAR NOT NULL, http_method VARCHAR NOT NULL, by_ext_id VARCHAR NOT NULL, by_ext_name VARCHAR NOT NULL, etag VARCHAR NOT NULL, last_modified VARCHAR NOT NULL, mime_type VARCHAR(255) NOT NULL, original_mime_type VARCHAR(255) NOT NULL);',
         'CREATE TABLE downloads_url_chains(id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index));']
    s += [f'INSERT INTO urls VALUES({i},{q(u)},{q(t)},{n},{ty},{lv},0);' for i, u, t, n, ty, lv in urls]
    prev = 0
    for k, (t, u, _, tr) in enumerate(VISITS, 1):
        dur = 0 if k == len(VISITS) else (webkit(VISITS[k][0]) - webkit(t)) // 2
        s.append(f'INSERT INTO visits VALUES({k},{seen[u]},{webkit(t)},{prev if tr == 0 else 0},{tr | 0x30000000},0,{dur});'); prev = k
    for k, term in SEARCHES.items(): s.append(f'INSERT INTO keyword_search_terms VALUES(2,{seen[VISITS[k][1]]},{q(term)},{q(term)});')
    t0, path = '2026-03-04T17:33:52Z', 'C:\\Users\\Petra\\Downloads\\Harbourline_refund_4471.pdf'
    s.append(f"INSERT INTO downloads VALUES(1,'6f2a1c9e-4b7d-4e10-9a33-0c5d2b8e7f41',{q(path)},{q(path)},{webkit(t0)},48213,48213,1,0,0,X'',{webkit(t0) + 900000},1,{webkit('2026-03-04T17:34:05Z')},0,"
             f"'https://harbour-line-portal.test/r/4400/receipt','https://harbour-line-portal.test/','https://harbour-line-portal.test/r/4400/receipt','https://harbour-line-portal.test/r/4400/fee/paid','GET','','','','','application/pdf','application/pdf');")
    s.append("INSERT INTO downloads_url_chains VALUES(1,0,'https://harbour-line-portal.test/r/4400/receipt.pdf');")
    s.append("INSERT INTO downloads_url_chains VALUES(1,1,'https://cdn.harbour-line-portal.test/files/receipt-4471.pdf');")
    return sqlite_bytes('\n'.join(s))

def shortcuts():
    s = ['CREATE TABLE omni_box_shortcuts(id VARCHAR PRIMARY KEY, text VARCHAR, fill_into_edit VARCHAR, url VARCHAR, contents VARCHAR, contents_class VARCHAR, description VARCHAR, description_class VARCHAR, transition INTEGER, type INTEGER, keyword VARCHAR, last_access_time INTEGER, number_of_hits INTEGER);']
    for k, (text, v, n) in enumerate(TYPED, 1):
        s.append(f"INSERT INTO omni_box_shortcuts VALUES('00000000-0000-4000-8000-00000000000{k}',{q(text)},{q(v[1])},{q(v[1])},{q(v[2])},'0,0','','',1,0,'',{webkit(v[0])},{n});")
    return sqlite_bytes('\n'.join(s))

def web_data():
    s = ['CREATE TABLE autofill(name VARCHAR, value VARCHAR, value_lower VARCHAR, date_created INTEGER DEFAULT 0, date_last_used INTEGER DEFAULT 0, count INTEGER DEFAULT 1, PRIMARY KEY (name, value));']
    s += [f'INSERT INTO autofill VALUES({q(n)},{q(v)},{q(v.lower())},{unix(a)},{unix(b)},{c});' for n, v, c, a, b in FORM]
    return sqlite_bytes('\n'.join(s))

def login_data():
    s = ['CREATE TABLE logins(origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, username_value VARCHAR, password_element VARCHAR, password_value BLOB, submit_element VARCHAR, signon_realm VARCHAR NOT NULL, date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT NULL, password_type INTEGER, times_used INTEGER, date_last_used INTEGER NOT NULL DEFAULT 0);',
         # the password column holds no password: the profile is made up, and the app never reads that column anyway
         f"INSERT INTO logins VALUES('https://harbour-line-portal.test/r/4400/claim','https://harbour-line-portal.test/r/4400/claim','email','p.lind@example.net','password',X'','','https://harbour-line-portal.test/',{webkit('2026-03-04T17:05:52Z')},0,0,0,2,{webkit('2026-03-06T07:48:35Z')});",
         f"INSERT INTO logins VALUES('https://coins-now.example/login','https://coins-now.example/login','user','p.lind@example.net','pass',X'','','https://coins-now.example/',{webkit('2026-03-04T17:12:30Z')},0,0,0,1,{webkit('2026-03-04T17:12:30Z')});"]
    return sqlite_bytes('\n'.join(s))

PREFS = {'account_info': [{'email': 'p.lind@example.net', 'full_name': 'Petra Lind', 'given_name': 'Petra', 'gaia': '000000000000000000001', 'hd': 'NO_HOSTED_DOMAIN'}],
         'profile': {'name': 'Petra', 'creation_time': str(webkit('2026-02-14T10:40:00Z'))},
         'download': {'default_directory': 'C:\\Users\\Petra\\Downloads'},
         'extensions': {'settings': {'aapocclcgogkmnckokdopfmhonfmgoek': {'from_webstore': True, 'location': 1, 'state': 1, 'install_time': str(webkit('2026-02-14T10:45:00Z')),
                                                                          'manifest': {'name': 'Google Translate', 'version': '2.0.13', 'permissions': ['activeTab', 'contextMenus', 'storage']}}}}}
BOOKMARKS = {'version': 1, 'roots': {
  'bookmark_bar': {'type': 'folder', 'name': 'Bookmarks bar', 'children': [
    {'type': 'url', 'name': 'Harbourline refund claim', 'url': 'https://harbour-line-portal.test/r/4400/status', 'date_added': str(webkit('2026-03-04T17:33:45Z'))},
    {'type': 'url', 'name': 'Harbourline Marine', 'url': 'https://harbourline-marine.example/', 'date_added': str(webkit('2026-02-20T19:10:00Z'))}]},
  'other': {'type': 'folder', 'name': 'Other bookmarks', 'children': []}}}

def profile_zip():
    b = io.BytesIO(); base = 'Google/Chrome/User Data/Default/'
    with zipfile.ZipFile(b, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in [('History', history()), ('Shortcuts', shortcuts()), ('Web Data', web_data()), ('Login Data', login_data()),
                           ('Preferences', json.dumps(PREFS, indent=1)), ('Bookmarks', json.dumps(BOOKMARKS, indent=1))]:
            zi = zipfile.ZipInfo(base + name, (2026, 3, 8, 10, 15, 0)); zi.compress_type = zipfile.ZIP_DEFLATED; z.writestr(zi, data)
    return b.getvalue()

# ---------------------------------------------------------------- the shop office PC's Security log
def load_make_evtx():
    spec = importlib.util.spec_from_file_location('make_evtx', os.path.join('tests', 'fixtures', 'make_evtx.py'))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

def security_log():
    M = load_make_evtx(); L = M.Log(); S, U32, HX, SID, GUID = M.T_WSTR, M.T_U32, M.T_HEX64, M.T_SID, M.T_GUID
    HOST = 'OFFICE-PC2.harbourline-marine.example'; SEC = dict(provider='Microsoft-Windows-Security-Auditing', channel='Security', computer=HOST)
    def logon(t, user, ltype, ip, lid, ws, rid, proc='C:\\Windows\\System32\\svchost.exe'):
        L.add(dict(SEC, id=4624, task=12544, time=t, fields=[('SubjectUserSid', SID, 'S-1-5-18'), ('SubjectUserName', S, 'OFFICE-PC2$'), ('SubjectDomainName', S, 'HARBOURLINE'), ('SubjectLogonId', HX, 0x3e7),
            ('TargetUserSid', SID, 'S-1-5-21-4000000001-4000000002-4000000003-' + str(rid)), ('TargetUserName', S, user), ('TargetDomainName', S, 'OFFICE-PC2'), ('TargetLogonId', HX, lid), ('LogonType', U32, ltype),
            ('LogonProcessName', S, 'User32' if ltype in (2, 10) else 'NtLmSsp'), ('AuthenticationPackageName', S, 'Negotiate' if ltype != 3 else 'NTLM'), ('WorkstationName', S, ws),
            ('LogonGuid', GUID, '{00000000-0000-0000-0000-000000000000}'), ('ProcessName', S, proc), ('IpAddress', S, ip), ('IpPort', S, '0' if ip in ('-', '127.0.0.1') else '50214')]))
    logon('2026-03-04T06:58:20.000Z', 'k.voss', 2, '127.0.0.1', 0x2a11f, 'OFFICE-PC2', 1001, proc='C:\\Windows\\System32\\winlogon.exe')
    for k in range(14):                                   # the spray: four account names, one address, every four seconds
        L.add(dict(SEC, id=4625, task=12544, level=0, keywords=0x8010000000000000, time='2026-03-04T11:52:%02d.300Z' % (k * 4), fields=[('SubjectUserSid', SID, 'S-1-0-0'), ('SubjectUserName', S, '-'),
            ('SubjectDomainName', S, '-'), ('SubjectLogonId', HX, 0), ('TargetUserSid', SID, 'S-1-0-0'), ('TargetUserName', S, ['administrator', 'office', 'k.voss', 'backup'][k % 4]),
            ('TargetDomainName', S, 'OFFICE-PC2'), ('Status', M.T_HEX32, 0xc000006d), ('FailureReason', S, '%%2313'), ('SubStatus', M.T_HEX32, 0xc000006a), ('LogonType', U32, 3),
            ('LogonProcessName', S, 'NtLmSsp'), ('AuthenticationPackageName', S, 'NTLM'), ('WorkstationName', S, 'DESKTOP-L4MP'), ('IpAddress', S, PORTAL), ('IpPort', S, str(50100 + k))]))
    logon('2026-03-04T11:58:03.500Z', 'backup', 10, PORTAL, 0x5c3d0, 'DESKTOP-L4MP', 1003)
    L.add(dict(SEC, id=4672, task=12548, time='2026-03-04T11:58:03.510Z', fields=[('SubjectUserSid', SID, 'S-1-5-21-4000000001-4000000002-4000000003-1003'), ('SubjectUserName', S, 'backup'),
        ('SubjectDomainName', S, 'OFFICE-PC2'), ('SubjectLogonId', HX, 0x5c3d0), ('PrivilegeList', S, 'SeBackupPrivilege\r\n\t\t\tSeRestorePrivilege')]))
    def proc(t, image, cmd, parent, pid):
        L.add(dict(SEC, id=4688, version=2, task=13312, time=t, fields=[('SubjectUserSid', SID, 'S-1-5-21-4000000001-4000000002-4000000003-1003'), ('SubjectUserName', S, 'backup'),
            ('SubjectDomainName', S, 'OFFICE-PC2'), ('SubjectLogonId', HX, 0x5c3d0), ('NewProcessId', HX, pid), ('NewProcessName', S, image), ('TokenElevationType', S, '%%1936'),
            ('ProcessId', HX, 0x1b70), ('CommandLine', S, cmd), ('TargetUserSid', SID, 'S-1-0-0'), ('TargetUserName', S, '-'), ('TargetDomainName', S, '-'), ('TargetLogonId', HX, 0),
            ('ParentProcessName', S, parent), ('MandatoryLabel', SID, 'S-1-16-12288')]))
    AWS, CMD = 'C:\\Program Files\\Amazon\\AWSCLIV2\\aws.exe', 'C:\\Windows\\System32\\cmd.exe'
    proc('2026-03-04T11:59:12.000Z', CMD, 'cmd.exe', 'C:\\Windows\\explorer.exe', 0x1c04)
    proc('2026-03-04T11:59:30.000Z', 'C:\\Windows\\System32\\whoami.exe', 'whoami', CMD, 0x1c20)
    proc('2026-03-04T12:07:41.000Z', AWS, 'aws sts get-caller-identity', CMD, 0x1d10)
    proc('2026-03-04T12:08:05.000Z', AWS, 'aws s3 ls s3://harbourline-shop-orders/exports/', CMD, 0x1d2c)
    proc('2026-03-04T12:10:22.000Z', AWS, 'aws s3 cp s3://harbourline-shop-orders/exports/customers-2026-03.csv C:\\Users\\backup\\Desktop\\c.csv', CMD, 0x1d48)
    proc('2026-03-04T12:11:02.000Z', AWS, 'aws s3 cp s3://harbourline-shop-orders/exports/orders-4400-4800.csv C:\\Users\\backup\\Desktop\\o.csv', CMD, 0x1d64)
    proc('2026-03-04T12:13:30.000Z', AWS, 'aws iam create-access-key --user-name office-backup', CMD, 0x1d80)
    proc('2026-03-04T12:15:48.000Z', 'C:\\Windows\\System32\\wevtutil.exe', 'wevtutil cl System', CMD, 0x1d9c)
    L.add(dict(SEC, id=4634, task=12545, time='2026-03-04T12:16:30.000Z', fields=[('TargetUserSid', SID, 'S-1-5-21-4000000001-4000000002-4000000003-1003'), ('TargetUserName', S, 'backup'),
        ('TargetDomainName', S, 'OFFICE-PC2'), ('TargetLogonId', HX, 0x5c3d0), ('LogonType', U32, 10)]))
    for k in range(24):                                   # the office's own background noise: the file server checking in
        logon('2026-03-04T%02d:%02d:00.000Z' % (7 + k // 4, (k % 4) * 15), 'OFFICE-PC2$', 3, '192.168.10.%d' % (2 + k % 2), 0x60000 + k, '-', 500, proc='-')
    return L

# ---------------------------------------------------------------- the shop's CloudTrail
def ct(t, name, src, ip, ua, user='office-backup', req=None, err=None, resp=None, ro=True, mfa=None):
    e = {'eventVersion': '1.09', 'userIdentity': {'type': 'IAMUser', 'principalId': 'AIDAEXAMPLEOFFICEBK01' if user == 'office-backup' else 'AIDAEXAMPLEKVOSS0001',
         'arn': 'arn:aws:iam::111122223333:user/' + user, 'accountId': '111122223333', 'userName': user},
         'eventTime': t, 'eventSource': src + '.amazonaws.com', 'eventName': name, 'awsRegion': 'eu-north-1', 'sourceIPAddress': ip, 'userAgent': ua,
         'requestParameters': req, 'responseElements': resp, 'readOnly': ro, 'eventType': 'AwsApiCall' if name != 'ConsoleLogin' else 'AwsConsoleSignIn',
         'recipientAccountId': '111122223333', 'eventID': '00000000-0000-4000-8000-%012d' % (unix(t) % 10**12)}
    if err: e['errorCode'], e['errorMessage'] = err, 'User: arn:aws:iam::111122223333:user/office-backup is not authorized to perform: cloudtrail:' + name
    if mfa: e['additionalEventData'] = {'MFAUsed': mfa}
    if src == 's3' and name in ('GetObject', 'PutObject', 'ListObjects'): e['eventCategory'] = 'Data'
    return e

def cloudtrail():
    CLI, CLI2, B = 'aws-cli/2.15.30 md/Botocore#1.34.30 os/windows#10 md/command#s3.cp', 'aws-cli/2.15.30 md/Botocore#1.34.30 os/linux#6.1 md/command#s3.cp', 'harbourline-shop-orders'
    NIGHT = 'aws-cli/2.15.30 md/Botocore#1.34.30 os/windows#10 md/command#s3.cp'
    R = [ct('2026-03-03T02:00:14Z', 'PutObject', 's3', OFFICE, NIGHT, req={'bucketName': B, 'key': 'exports/orders-2026-03-03.csv'}, ro=False),
         ct('2026-03-04T02:00:11Z', 'PutObject', 's3', OFFICE, NIGHT, req={'bucketName': B, 'key': 'exports/orders-2026-03-04.csv'}, ro=False),
         # from the portal's server, through the office PC's stored key, minutes after the remote desktop session began
         ct('2026-03-04T12:07:42Z', 'GetCallerIdentity', 'sts', PORTAL, CLI.replace('s3.cp', 'sts.get-caller-identity')),
         ct('2026-03-04T12:08:06Z', 'ListObjects', 's3', PORTAL, CLI.replace('s3.cp', 's3.ls'), req={'bucketName': B, 'prefix': 'exports/', 'delimiter': '/'}),
         ct('2026-03-04T12:10:23Z', 'GetObject', 's3', PORTAL, CLI, req={'bucketName': B, 'key': 'exports/customers-2026-03.csv'}),
         ct('2026-03-04T12:11:03Z', 'GetObject', 's3', PORTAL, CLI, req={'bucketName': B, 'key': 'exports/orders-4400-4800.csv'}),
         ct('2026-03-04T12:13:31Z', 'CreateAccessKey', 'iam', PORTAL, CLI.replace('s3.cp', 'iam.create-access-key'), req={'userName': 'office-backup'}, ro=False,
            resp={'accessKey': {'userName': 'office-backup', 'status': 'Active', 'createDate': 'Mar 4, 2026 12:13:31 PM'}}),
         ct('2026-03-04T12:14:20Z', 'StopLogging', 'cloudtrail', PORTAL, CLI.replace('s3.cp', 'cloudtrail.stop-logging'), req={'name': 'shop-trail'}, err='AccessDenied', ro=False),
         ct('2026-03-05T02:00:12Z', 'PutObject', 's3', OFFICE, NIGHT, req={'bucketName': B, 'key': 'exports/orders-2026-03-05.csv'}, ro=False),
         # six days later, with the new key, from the "faster server" the staff chat moved the portal to
         ct('2026-03-10T08:40:51Z', 'ListObjects', 's3', NEWBOX, CLI2.replace('s3.cp', 's3.ls'), req={'bucketName': B, 'prefix': 'exports/', 'delimiter': '/'}),
         ct('2026-03-10T08:41:12Z', 'GetObject', 's3', NEWBOX, CLI2, req={'bucketName': B, 'key': 'exports/orders-4800-5200.csv'}),
         # the shop notices
         ct('2026-03-11T07:02:09Z', 'ConsoleLogin', 'signin', OFFICE, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36', user='k.voss', mfa='Yes', ro=False,
            resp={'ConsoleLogin': 'Success'}),
         ct('2026-03-11T07:05:40Z', 'ListAccessKeys', 'iam', OFFICE, 'AWS Internal', user='k.voss', req={'userName': 'office-backup'}),
         ct('2026-03-11T07:06:15Z', 'UpdateAccessKey', 'iam', OFFICE, 'AWS Internal', user='k.voss', req={'userName': 'office-backup', 'status': 'Inactive'}, ro=False),
         ct('2026-03-11T07:06:52Z', 'DeleteAccessKey', 'iam', OFFICE, 'AWS Internal', user='k.voss', req={'userName': 'office-backup'}, ro=False)]
    return {'Records': R}

if __name__ == '__main__':
    open(os.path.join(OUT, 'lind-chrome-profile.zip'), 'wb').write(profile_zip())
    security_log().save(os.path.join(OUT, 'office-pc2-security.evtx'))
    open(os.path.join(OUT, 'shop-cloudtrail.json'), 'w', encoding='utf-8', newline='\n').write(json.dumps(cloudtrail(), indent=1) + '\n')
    print('wrote lind-chrome-profile.zip, office-pc2-security.evtx, shop-cloudtrail.json')
