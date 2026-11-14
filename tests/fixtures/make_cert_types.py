"""A small fictional company PKI for the "Types of certificates" chapter: a root, an identity CA that may
only issue client, email and document certificates, and one certificate of each kind it issues.
Everything is made up (Northwind Traders, *.northwind.example); the private keys are thrown away.
Run: python3 tests/fixtures/make_cert_types.py   (needs the Python cryptography package)"""
import os, datetime as dt
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

OUT = os.path.join(os.path.dirname(__file__), 'certs'); os.makedirs(OUT, exist_ok=True)
T0 = dt.datetime(2026, 3, 2, 9, 0)
def name(cn, ou=None, email=None):
    a = [x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'), x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Northwind Traders')]
    if ou: a.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    a.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    if email: a.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return x509.Name(a)
def ku(**k):
    d = dict(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False); d.update(k)
    return x509.KeyUsage(**d)
def build(subj, key, issuer, ikey, days, exts, serial):
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(issuer.subject if issuer else subj).public_key(key.public_key()).serial_number(serial)
         .not_valid_before(T0).not_valid_after(T0 + dt.timedelta(days=days))
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False))
    if issuer: b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), False)
    for e, crit in exts: b = b.add_extension(e, crit)
    return b.sign(ikey or key, hashes.SHA256())
aia = lambda: x509.AuthorityInformationAccess([x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier('http://pki.northwind.example/identity-ca-01.crt')),
                                               x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier('http://ocsp.northwind.example'))])
crl = lambda: x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier('http://pki.northwind.example/identity-ca-01.crl')], None, None, None)])
upn = lambda v: x509.OtherName(ObjectIdentifier('1.3.6.1.4.1.311.20.2.3'), b'\x0c' + bytes([len(v)]) + v.encode())
DOCSIGN, MSDOC = ObjectIdentifier('1.3.6.1.5.5.7.3.36'), ObjectIdentifier('1.3.6.1.4.1.311.10.3.12')

rk = ec.generate_private_key(ec.SECP384R1())
root = build(name('Northwind Root CA G1'), rk, None, None, 7300, [(x509.BasicConstraints(True, 1), True), (ku(key_cert_sign=True, crl_sign=True), True)], 0x4e57524f4f54)
ik = ec.generate_private_key(ec.SECP384R1())
ica = build(name('Northwind Identity CA 01'), ik, root, rk, 3650, [(x509.BasicConstraints(True, 0), True), (ku(digital_signature=True, key_cert_sign=True, crl_sign=True), True),
      (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SMARTCARD_LOGON, ExtendedKeyUsageOID.EMAIL_PROTECTION, DOCSIGN, MSDOC, ExtendedKeyUsageOID.TIME_STAMPING]), False),
      (x509.NameConstraints(permitted_subtrees=[x509.DNSName('corp.northwind.example'), x509.RFC822Name('northwind.example'), x509.RFC822Name('.northwind.example')], excluded_subtrees=None), True)], 0x1d01)
def leaf(fn, subj, days, exts, serial, rsa_key=False):
    k = rsa.generate_private_key(65537, 2048) if rsa_key else ec.generate_private_key(ec.SECP256R1())
    c = build(subj, k, ica, ik, days, exts + [(aia(), False), (crl(), False)], x509.random_serial_number())   # 159 random bits, as public CAs must use
    open(os.path.join(OUT, fn), 'wb').write(b''.join(x.public_bytes(serialization.Encoding.PEM) for x in (c, ica, root)))
leaf('type-client.pem', name('Dana Whitfield', 'Finance'), 365, [(x509.BasicConstraints(False, None), True), (ku(digital_signature=True), True), (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
     (x509.SubjectAlternativeName([x509.RFC822Name('dana.whitfield@northwind.example'), upn('dana.whitfield@corp.northwind.example')]), False)], 0x5c11e47a01, rsa_key=True)
leaf('type-device.pem', name('NWT-LT-04271.corp.northwind.example', 'Managed laptops'), 395, [(x509.BasicConstraints(False, None), True), (ku(digital_signature=True, key_encipherment=True), True), (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
     (x509.SubjectAlternativeName([x509.DNSName('NWT-LT-04271.corp.northwind.example')]), False)], 0xde71ce0427, rsa_key=True)
leaf('type-smime.pem', name('Dana Whitfield', None, 'dana.whitfield@northwind.example'), 730, [(x509.BasicConstraints(False, None), True), (ku(digital_signature=True, key_encipherment=True), True), (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), False),
     (x509.SubjectAlternativeName([x509.RFC822Name('dana.whitfield@northwind.example')]), False)], 0x5a1e0001, rsa_key=True)
leaf('type-docsign.pem', name('Dana Whitfield', 'Finance', 'dana.whitfield@northwind.example'), 730, [(x509.BasicConstraints(False, None), True), (ku(digital_signature=True, content_commitment=True), True), (x509.ExtendedKeyUsage([DOCSIGN, MSDOC]), False),
     (x509.SubjectAlternativeName([x509.RFC822Name('dana.whitfield@northwind.example')]), False)], 0xd0c51900)
leaf('type-tsa.pem', name('Northwind Timestamping Authority 2026'), 1825, [(x509.BasicConstraints(False, None), True), (ku(digital_signature=True), True), (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), True)], 0x75a2026)
open(os.path.join(OUT, 'type-clientca.pem'), 'wb').write(b''.join(x.public_bytes(serialization.Encoding.PEM) for x in (ica, root)))
print('wrote type-client, type-device, type-smime, type-docsign, type-tsa and type-clientca')
