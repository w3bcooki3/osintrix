"""Test and sample certificates for the Certificates section. Everything here is fictional
and made for this project: the keys are thrown away and nothing chains to a real CA.
Run: python3 tests/fixtures/make_certs.py   (needs the `cryptography` package)"""
import warnings; warnings.filterwarnings('ignore')
import datetime as dt, ipaddress, os, struct, base64
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding

OUT = os.path.join(os.path.dirname(__file__), 'certs'); os.makedirs(OUT, exist_ok=True)
U = dt.timezone.utc
def name(**kw):
    m = {'C': NameOID.COUNTRY_NAME, 'ST': NameOID.STATE_OR_PROVINCE_NAME, 'L': NameOID.LOCALITY_NAME, 'O': NameOID.ORGANIZATION_NAME, 'OU': NameOID.ORGANIZATIONAL_UNIT_NAME, 'CN': NameOID.COMMON_NAME, 'E': NameOID.EMAIL_ADDRESS}
    return x509.Name([x509.NameAttribute(m[k], v, _validate=False) for k, v in kw.items()])
def rsakey(bits=2048): return rsa.generate_private_key(public_exponent=65537, key_size=bits)
def ski(k): return x509.SubjectKeyIdentifier.from_public_key(k.public_key())
def aki(k): return x509.AuthorityKeyIdentifier.from_issuer_public_key(k.public_key())
def save(fn, cert): open(os.path.join(OUT, fn), 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
def build(subject, issuer, key, ikey, nb, na, exts, serial=None, alg=hashes.SHA256(), pad=None):
    b = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(serial or x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
    for e, c in exts: b = b.add_extension(e, critical=c)
    if isinstance(ikey, ed25519.Ed25519PrivateKey): return b.sign(ikey, None)
    return b.sign(ikey, alg, rsa_padding=pad) if pad else b.sign(ikey, alg)

# a signed certificate timestamp list (RFC 6962), with made-up log IDs and empty signatures for the sample
def sct(log_id, ms):
    body = b'\x00' + log_id + struct.pack('>Q', ms) + b'\x00\x00' + b'\x04\x03' + struct.pack('>H', 8) + b'\x30\x06\x02\x01\x01\x02\x01\x01'
    return struct.pack('>H', len(body)) + body
scts = sct(b'\x11' * 32, 1793243662000) + sct(b'\x22' * 32, 1793243662500)
sct_ext = x509.UnrecognizedExtension(ObjectIdentifier('1.3.6.1.4.1.11129.2.4.2'), b'\x04' + bytes([len(scts) + 2]) + struct.pack('>H', len(scts)) + scts)

rk, ik = rsakey(), rsakey()
root_n, int_n = name(C='US', O='Example Trust Services', CN='Example Root CA X1'), name(C='US', O='Example Trust Services', CN='Example Issuing CA R1')
root = build(root_n, root_n, rk, rk, dt.datetime(2020, 1, 1, tzinfo=U), dt.datetime(2045, 1, 1, tzinfo=U),
  [(x509.BasicConstraints(ca=True, path_length=None), True), (x509.KeyUsage(False, False, False, False, False, True, True, False, False), True), (ski(rk), False)])
inter = build(int_n, root_n, ik, rk, dt.datetime(2024, 3, 1, tzinfo=U), dt.datetime(2030, 3, 1, tzinfo=U),
  [(x509.BasicConstraints(ca=True, path_length=0), True), (x509.KeyUsage(True, False, False, False, False, True, True, False, False), True), (ski(ik), False), (aki(rk), False),
   (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False),
   (x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier('http://crl.example-trust.test/root-x1.crl')], None, None, None)]), False)])
save('root.pem', root); save('intermediate.pem', inter)

lk = rsakey()
leaf = build(name(CN='secure-acme-login.com'), int_n, lk, ik, dt.datetime(2026, 10, 29, 3, 14, 22, tzinfo=U), dt.datetime(2027, 1, 27, 3, 14, 21, tzinfo=U), [
  (x509.SubjectAlternativeName([x509.DNSName('secure-acme-login.com'), x509.DNSName('www.secure-acme-login.com'), x509.DNSName('mail.secure-acme-login.com'), x509.DNSName('acme-sso.microsoftonline-auth.com'), x509.DNSName('files-acme.net'), x509.IPAddress(ipaddress.ip_address('185.220.101.47'))]), False),
  (x509.BasicConstraints(ca=False, path_length=None), True), (x509.KeyUsage(True, False, True, False, False, False, False, False, False), True),
  (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False), (ski(lk), False), (aki(ik), False),
  (x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier('http://ocsp.example-trust.test')), x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier('http://certs.example-trust.test/r1.der'))]), False),
  (x509.CertificatePolicies([x509.PolicyInformation(ObjectIdentifier('2.23.140.1.2.1'), None)]), False), (sct_ext, False)])
save('leaf-phish.pem', leaf)
open(os.path.join(OUT, 'leaf-phish.der'), 'wb').write(leaf.public_bytes(serialization.Encoding.DER))
open(os.path.join(OUT, 'chain-phish.pem'), 'wb').write(b''.join(c.public_bytes(serialization.Encoding.PEM) for c in (inter, leaf)))   # deliberately out of order, no root

ek = ec.generate_private_key(ec.SECP256R1())
ov = build(name(C='GB', L='London', O='Acme Industries Ltd', CN='portal.acme.example'), int_n, ek, ik, dt.datetime(2026, 6, 1, tzinfo=U), dt.datetime(2027, 6, 1, tzinfo=U), [
  (x509.SubjectAlternativeName([x509.DNSName('portal.acme.example'), x509.DNSName('*.portal.acme.example')]), False), (x509.BasicConstraints(ca=False, path_length=None), True),
  (x509.KeyUsage(True, False, False, False, False, False, False, False, False), True), (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False), (aki(ik), False),
  (x509.CertificatePolicies([x509.PolicyInformation(ObjectIdentifier('2.23.140.1.2.2'), [x509.UserNotice(None, None), 'https://cps.example-trust.test'][1:])]), False),
  (x509.TLSFeature([x509.TLSFeatureType.status_request]), False)])
save('ov-ecdsa.pem', ov)
open(os.path.join(OUT, 'bundle.p7b'), 'wb').write(__import__('cryptography.hazmat.primitives.serialization.pkcs7', fromlist=['x']).serialize_certificates([ov, inter, root], serialization.Encoding.DER))

ck = rsakey()
cs_n = name(C='Earth', ST='Cyberspace', L='Somewhere', O='cobaltstrike', OU='AdvancedPenTesting', CN='Major Cobalt Strike')
save('cobaltstrike-default.pem', build(cs_n, cs_n, ck, ck, dt.datetime(2025, 5, 20, tzinfo=U), dt.datetime(2035, 5, 18, tzinfo=U), [], serial=146473198))

xk = rsakey()
save('expired.pem', build(name(C='GB', O='Acme Industries Ltd', CN='vpn.acme.example'), int_n, xk, ik, dt.datetime(2025, 10, 1, tzinfo=U), dt.datetime(2026, 10, 29, tzinfo=U), [
  (x509.SubjectAlternativeName([x509.DNSName('vpn.acme.example')]), False), (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)]))

# SHA-1 and 1024-bit RSA: the cryptography package refuses to sign with SHA-1, so openssl makes this one
import subprocess, tempfile
with tempfile.TemporaryDirectory() as t:
    subprocess.run(['openssl', 'req', '-x509', '-sha1', '-newkey', 'rsa:1024', '-nodes', '-keyout', os.path.join(t, 'k.pem'), '-out', os.path.join(OUT, 'weak-sha1.pem'), '-days', '7300', '-set_serial', '1',
      '-subj', '/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=old-printer.acme.local', '-addext', 'basicConstraints=critical,CA:FALSE'], check=True, capture_output=True)

dk = ed25519.Ed25519PrivateKey.generate(); dn = name(CN='ed25519.acme.example')
save('ed25519.pem', build(dn, dn, dk, dk, dt.datetime(2026, 1, 1, tzinfo=U), dt.datetime(2028, 1, 1, tzinfo=U), [(x509.SubjectAlternativeName([x509.DNSName('ed25519.acme.example')]), False)], alg=None))

xk2 = ec.generate_private_key(ec.SECP384R1()); xn = name(CN='ec384.acme.example', O='Acme Industries Ltd')
save('ecdsa-p384.pem', build(xn, xn, xk2, xk2, dt.datetime(2026, 1, 1, tzinfo=U), dt.datetime(2028, 1, 1, tzinfo=U), [(x509.SubjectAlternativeName([x509.DNSName('ec384.acme.example')]), False)], alg=hashes.SHA384()))

pk = rsakey(); pn = name(CN='pss.acme.example')
save('rsa-pss.pem', build(pn, pn, pk, pk, dt.datetime(2026, 1, 1, tzinfo=U), dt.datetime(2028, 1, 1, tzinfo=U), [(x509.SubjectAlternativeName([x509.DNSName('pss.acme.example')]), False)],
  pad=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)))

ak = rsakey()
upn = x509.OtherName(ObjectIdentifier('1.3.6.1.4.1.311.20.2.3'), b'\x0c' + bytes([len('j.okafor@corp.example')]) + b'j.okafor@corp.example')
tmpl = 'User'.encode('utf-16-be'); tmpl_ext = x509.UnrecognizedExtension(ObjectIdentifier('1.3.6.1.4.1.311.20.2'), b'\x1e' + bytes([len(tmpl)]) + tmpl)
save('adcs-user.pem', build(name(CN='Jane Okafor'), name(CN='CORP-CA'), ak, ik, dt.datetime(2026, 9, 1, tzinfo=U), dt.datetime(2027, 9, 1, tzinfo=U), [
  (x509.SubjectAlternativeName([upn, x509.RFC822Name('j.okafor@corp.example')]), False),
  (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ObjectIdentifier('1.3.6.1.4.1.311.20.2.2'), ExtendedKeyUsageOID.EMAIL_PROTECTION]), False), (tmpl_ext, False)]))

qk = rsakey()
csr = (x509.CertificateSigningRequestBuilder().subject_name(name(C='GB', O='Acme Industries Ltd', CN='api.acme.example'))
  .add_extension(x509.SubjectAlternativeName([x509.DNSName('api.acme.example'), x509.DNSName('api-v2.acme.example')]), critical=False)
  .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
  .add_attribute(ObjectIdentifier('1.2.840.113549.1.9.7'), b'notsecret').sign(qk, hashes.SHA256()))
open(os.path.join(OUT, 'request.csr'), 'wb').write(csr.public_bytes(serialization.Encoding.PEM))
nk = rsakey(); csr2 = x509.CertificateSigningRequestBuilder().subject_name(name(CN='no-san.acme.example')).sign(nk, hashes.SHA256())
open(os.path.join(OUT, 'request-nosan.csr'), 'wb').write(csr2.public_bytes(serialization.Encoding.PEM))
open(os.path.join(OUT, 'private-key.pem'), 'wb').write(nk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
print('written to', OUT, sorted(os.listdir(OUT)))
