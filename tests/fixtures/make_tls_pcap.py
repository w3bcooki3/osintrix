"""A real TLS 1.2 handshake (openssl s_server <-> s_client on localhost, recorded through a relay) written
out as a pcap with made-up addresses, so the PCAP reader's certificate extraction can be tested.
Run: python3 tests/fixtures/make_tls_pcap.py   (needs openssl and the `cryptography` package)"""
import os, socket, struct, subprocess, tempfile, threading, time, datetime as dt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
OUT = os.path.join(os.path.dirname(__file__), 'tls12-cert.pcap')
k = rsa.generate_private_key(public_exponent=65537, key_size=2048); n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'shop.acme.example')])
c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(x509.random_serial_number())
     .not_valid_before(dt.datetime(2026, 1, 1)).not_valid_after(dt.datetime(2028, 1, 1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('shop.acme.example'), x509.DNSName('pay.acme.example')]), False).sign(k, hashes.SHA256()))
t = tempfile.mkdtemp(); open(t + '/c.pem', 'wb').write(c.public_bytes(serialization.Encoding.PEM))
open(t + '/k.pem', 'wb').write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
srv = subprocess.Popen(['openssl', 's_server', '-accept', '127.0.0.1:9444', '-cert', t + '/c.pem', '-key', t + '/k.pem', '-tls1_2', '-quiet'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.8)
rec = []   # (direction 0 = client->server, bytes)
def relay():
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(('127.0.0.1', 9443)); ls.listen(1)
    a, _ = ls.accept(); b = socket.create_connection(('127.0.0.1', 9444)); a.settimeout(0.5); b.settimeout(0.5); idle = 0
    while idle < 6:
        moved = False
        for s, d, dirn in ((a, b, 0), (b, a, 1)):
            try: x = s.recv(65536)
            except socket.timeout: continue
            if not x: idle = 99; break
            rec.append((dirn, x)); d.sendall(x); moved = True
        idle = 0 if moved else idle + 1
    a.close(); b.close(); ls.close()
th = threading.Thread(target=relay); th.start(); time.sleep(0.2)
subprocess.run(['openssl', 's_client', '-connect', '127.0.0.1:9443', '-servername', 'shop.acme.example', '-tls1_2'], input=b'', capture_output=True, timeout=20)
th.join(10); srv.kill()
# write a pcap: Ethernet / IPv4 / TCP, client 10.0.0.5:51515 -> server 203.0.113.10:443
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16; return ~s & 0xffff
C, S = bytes([10, 0, 0, 5]), bytes([203, 0, 113, 10]); seq = [1000, 5000]; pk = []; ts = 1793243662.0
def pkt(dirn, flags, data=b''):
    global ts
    src, dst, sp, dp = (C, S, 51515, 443) if dirn == 0 else (S, C, 443, 51515)
    tcp = struct.pack('!HHIIBBHHH', sp, dp, seq[dirn], seq[1 - dirn], 5 << 4, flags, 65535, 0, 0) + data
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst); ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    frame = eth + ip + tcp; ts += 0.01; pk.append(struct.pack('<IIII', int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame)
    seq[dirn] += len(data) + (1 if flags & 0x02 else 0)
pkt(0, 0x02); pkt(1, 0x12); pkt(0, 0x10)
for d, x in rec:
    for i in range(0, len(x), 1400): pkt(d, 0x18, x[i:i + 1400])
pkt(0, 0x11); pkt(1, 0x11)
open(OUT, 'wb').write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + b''.join(pk))
print('wrote', OUT, len(rec), 'segments', sum(len(x) for _, x in rec), 'bytes')
