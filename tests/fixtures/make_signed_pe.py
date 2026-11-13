"""A tiny signed Windows program for the Certificates section's Authenticode tests.
Everything is fictional: a made-up publisher, a throwaway CA, and a program that only returns.
Run: python3 tests/fixtures/make_signed_pe.py   (needs the openssl and osslsigncode commands)"""
import os, struct, subprocess, tempfile, shutil

OUT = os.path.join(os.path.dirname(__file__), 'certs'); os.makedirs(OUT, exist_ok=True)

def pe():
    """A minimal valid PE32+ executable: one .text section holding `xor eax,eax; ret`."""
    dos = bytearray(0x80); dos[0:2] = b'MZ'; struct.pack_into('<I', dos, 0x3c, 0x80)
    coff = struct.pack('<HHIIIHH', 0x8664, 1, 0x65000000, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into('<HBBIIIII', opt, 0, 0x20b, 14, 0, 0x200, 0, 0, 0x1000, 0x1000)
    struct.pack_into('<Q', opt, 24, 0x140000000)                     # image base
    struct.pack_into('<II', opt, 32, 0x1000, 0x200)                   # section / file alignment
    struct.pack_into('<HHHHHH', opt, 40, 6, 0, 0, 0, 6, 0)            # OS / image / subsystem versions
    struct.pack_into('<IIII', opt, 56, 0x2000, 0x200, 0, 3)           # size of image, size of headers, checksum, subsystem (console)
    struct.pack_into('<H', opt, 70, 0x8160)                           # DLL characteristics
    struct.pack_into('<QQQQ', opt, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into('<I', opt, 108, 16)                              # number of data directories
    sec = struct.pack('<8sIIIIIIHHI', b'.text', 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    head = bytes(dos) + b'PE\0\0' + coff + bytes(opt) + sec
    head += b'\0' * (0x200 - len(head))
    body = b'\x31\xc0\xc3' + b'\xcc' * (0x200 - 3)
    return head + body

def run(*a): subprocess.run(a, check=True, capture_output=True)

t = tempfile.mkdtemp()
try:
    j = lambda n: os.path.join(t, n)
    open(j('ca.cnf'), 'w').write('[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n'
                                 '[v3_cs]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', j('ca.key'), '-out', j('ca.pem'), '-days', '7300', '-subj', '/C=US/O=Example Trust Services/CN=Example Code Signing CA', '-extensions', 'v3_ca', '-config', j('ca.cnf'), '-set_serial', '0x4c0de5')
    run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', j('cs.key'), '-out', j('cs.csr'), '-subj', '/C=US/ST=Washington/L=Redmond/O=Fabrikam Tools Ltd/CN=Fabrikam Tools Ltd')
    run('openssl', 'x509', '-req', '-in', j('cs.csr'), '-CA', j('ca.pem'), '-CAkey', j('ca.key'), '-out', j('cs.pem'), '-days', '1095', '-extfile', j('ca.cnf'), '-extensions', 'v3_cs', '-set_serial', '0x0a1b2c3d4e5f6071')
    open(j('chain.pem'), 'w').write(open(j('cs.pem')).read() + open(j('ca.pem')).read())
    open(j('a.exe'), 'wb').write(pe())
    run('osslsigncode', 'sign', '-certs', j('chain.pem'), '-key', j('cs.key'), '-h', 'sha256', '-n', 'Fabrikam Updater', '-i', 'https://fabrikam.example/updater',
        '-in', j('a.exe'), '-out', os.path.join(OUT, 'signed.exe'))
    b = bytearray(open(os.path.join(OUT, 'signed.exe'), 'rb').read()); b[0x200 + 1] ^= 0xff          # change the program after signing
    open(os.path.join(OUT, 'signed-tampered.exe'), 'wb').write(b)
    print('wrote signed.exe and signed-tampered.exe')
finally:
    shutil.rmtree(t)
