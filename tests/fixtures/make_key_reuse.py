"""Two fictional certificates that share one private key, and one whose fields carry markup (the keys are thrown away).
Run: python3 tests/fixtures/make_key_reuse.py   (needs the openssl command)"""
import os, subprocess, tempfile, shutil
OUT = os.path.join(os.path.dirname(__file__), 'certs')
t = tempfile.mkdtemp()
try:
    k = os.path.join(t, 'k.pem')
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', k], check=True, capture_output=True)
    for fn, cn, san in [('reuse-a.pem', 'update-cdn.example', 'DNS:update-cdn.example,DNS:www.update-cdn.example'), ('reuse-b.pem', 'mail-relay.example', 'DNS:mail-relay.example')]:
        subprocess.run(['openssl', 'req', '-x509', '-key', k, '-out', os.path.join(OUT, fn), '-days', '365', '-subj', '/CN=' + cn, '-addext', 'subjectAltName=' + san, '-addext', 'extendedKeyUsage=serverAuth', '-addext', 'basicConstraints=critical,CA:FALSE'], check=True, capture_output=True)
    print('wrote reuse-a.pem and reuse-b.pem')
finally:
    shutil.rmtree(t)

# a certificate whose names and fields carry markup and a spreadsheet formula, to prove they stay text
import datetime as dt
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '<img src=x onerror=window.__pwned=1>.evil.test'), x509.NameAttribute(NameOID.ORGANIZATION_NAME, '"><script>window.__pwned=2</script>')])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(dt.datetime(2026, 1, 1)).not_valid_after(dt.datetime(2027, 1, 1))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName('<svg/onload=window.__pwned=3>.evil.test'), x509.DNSName('=HYPERLINK("http://x.test")'), x509.UniformResourceIdentifier('javascript:window.__pwned=4')]), False)
         .sign(k, hashes.SHA256()))
    open(os.path.join(OUT, 'hostile.pem'), 'wb').write(c.public_bytes(serialization.Encoding.PEM)); print('wrote hostile.pem')
except Exception as e:
    print('skipped hostile.pem:', e)
