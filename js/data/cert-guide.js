/* "How certificates work": ten short chapters. Static, trusted HTML written for this app.
   Each chapter has flashcards (Q/A) that can go to the Notebook, a command, and an example to open. */
const CERT_GUIDE = [
{id:'tls', title:'How TLS uses certificates', lead:'A certificate answers one question for your browser: is the server I reached really the one whose name I typed?', sample:'phish', cmd:'openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null',
 body:`<div class="crtg-steps">
  <div><b>1 · Client hello</b><span>The browser says which name it wants (SNI) and which ciphers it supports. The name travels in the clear — that is what PCAPs show.</span></div>
  <div><b>2 · Server sends its chain</b><span>Its own certificate (the leaf) plus the intermediates. In TLS 1.3 this part is encrypted, so captures no longer show it.</span></div>
  <div><b>3 · Browser checks</b><span>The chain leads to a trusted root, the name is in the subject alternative names, today is inside the validity dates, and nothing says it was revoked.</span></div>
  <div><b>4 · Server proves the key</b><span>It signs the handshake with the private key that matches the certificate. A copied certificate is useless without that key.</span></div></div>
 <h3>What a certificate does not prove</h3>
 <p>It does not say the site is honest. A domain-validated certificate only proves someone controlled the domain when it was issued. Phishing sites get valid certificates in minutes, so the padlock means “encrypted to this name”, nothing more.</p>
 <h3>Where certificates turn up in an investigation</h3>
 <ul><li>Captured traffic (TLS 1.2 and older, or decrypted traffic).</li><li>Server scans: Censys and Shodan record the certificate every IP presents.</li><li>Certificate Transparency logs: every public certificate, searchable on crt.sh.</li><li>Endpoints: Windows certificate stores, code-signing on binaries, AD CS issued certificates.</li></ul>`,
 cards:[['What does the browser check about a server certificate?', 'That it chains to a trusted root, the name is in the SANs, it is within its validity dates, and it is not revoked; then that the server holds the matching private key.'],
  ['Why can you see the certificate in a TLS 1.2 capture but not in TLS 1.3?', 'TLS 1.3 encrypts the Certificate message; only the SNI in the ClientHello stays in the clear.'],
  ['What does a DV certificate prove?', 'Only that the requester controlled the domain at issuance — not who they are or that the site is honest.']]},

{id:'chain', title:'Chain of trust', lead:'Your browser trusts a few hundred root CAs. A website’s certificate is trusted only if it can be traced, signature by signature, back to one of them.', sample:'chain', cmd:'openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem',
 body:`<div class="crtg-dia"><div class="crtg-box root"><b>Root CA</b><small>Built into browsers and operating systems · self-signed · kept offline</small></div><div class="crtg-arw"><i></i>signs</div>
  <div class="crtg-box"><b>Intermediate CA</b><small>Does the daily issuing · can be revoked if compromised</small></div><div class="crtg-arw"><i></i>signs</div>
  <div class="crtg-box"><b>Leaf certificate</b><small>The website · not a CA</small></div></div>
 <h3>How each link is checked</h3>
 <p>The leaf’s <b>issuer</b> name must equal the intermediate’s <b>subject</b> name (and the authority key ID should match the issuer’s subject key ID). Then the leaf’s signature is checked with the intermediate’s public key. The same happens one level up, until a root the browser already trusts.</p>
 <h3>Why intermediates exist</h3>
 <p>Root keys are precious, so they stay offline and sign only a few intermediates. If an intermediate leaks, it can be revoked without replacing roots on billions of devices.</p>
 <h3>Common chain problems</h3>
 <ul><li><b>Missing intermediate:</b> the server only sends its leaf. Some browsers fetch the intermediate themselves; other clients fail.</li><li><b>Wrong order or extra certificates:</b> usually harmless, sometimes not.</li><li><b>Path length:</b> an intermediate with path length 0 may sign only end certificates.</li><li><b>Private roots:</b> companies and malware alike install their own root to make their certificates trusted on a machine — worth checking in incident response.</li></ul>`,
 cards:[['Why is a root CA certificate self-signed?', 'Nothing above it vouches for it — trust comes from it being shipped in the browser or operating system.'],
  ['How is a certificate linked to its issuer?', 'Its issuer name equals the issuer’s subject name (and AKI matches SKI); its signature verifies with the issuer’s public key.'],
  ['What does path length 0 on an intermediate mean?', 'It may issue only end-entity certificates, not further CAs.'],
  ['Why does installing a new root certificate on a machine matter in an investigation?', 'Anything signed by that root becomes trusted there — used by TLS-inspecting proxies and by malware to intercept traffic.']]},

{id:'inside', title:'What is inside a certificate', lead:'A certificate is a small signed document: who it is for, who vouches for it, when it is valid, the public key, and extensions that limit what it may do.', sample:'phish', cmd:'openssl x509 -in cert.pem -noout -text',
 body:`<div class="crtg-anno"><pre tabindex="0" aria-label="Annotated certificate">Certificate:
  Version: 3
  Serial Number: 04:7a:b6:7c:ee:d5:6f:47
  Signature Algorithm: sha256WithRSAEncryption
  Issuer: <span class="h">CN=Example Issuing CA R1</span>                    ①
  Validity
    Not Before: <span class="h">Oct 29 03:14:22 2026 GMT</span>                    ②
    Not After : Jan 27 03:14:21 2027 GMT
  Subject: <span class="h">CN=secure-acme-login.com</span>                        ③
  Subject Public Key Info: RSA 2048 bit
  X509v3 Subject Alternative Name:
    <span class="h">DNS:secure-acme-login.com, DNS:files-acme.net</span>    ④
  X509v3 Basic Constraints: critical CA:FALSE
  X509v3 Extended Key Usage: serverAuth
  CT Precertificate SCTs: <span class="h">2 logs</span>                         ⑤</pre>
 <ol><li><b>Issuer</b> — who vouches for it. Its signature is checked with the issuer’s public key.</li><li><b>Validity</b> — public TLS certificates are getting shorter: 398 days from 2020, 200 days from March 2026, 100 from March 2027 and 47 from March 2029.</li><li><b>Subject</b> — who it is for. DV certificates carry only a domain; OV and EV add the organisation.</li><li><b>SANs</b> — every name it covers. Browsers ignore the Common Name; investigators read these first.</li><li><b>SCTs</b> — proof it was published in Certificate Transparency logs, so it can be found on crt.sh.</li></ol></div>
 <h3>Extensions worth knowing</h3>
 <ul><li><b>Basic constraints</b> — is it a CA, and how deep may it issue.</li><li><b>Key usage / extended key usage</b> — what it may do: TLS server, client login, code signing, email, smart-card logon.</li><li><b>Authority information access</b> — where to fetch the issuer and (sometimes) an OCSP responder.</li><li><b>CRL distribution points</b> — where the revocation list lives.</li><li><b>Certificate policies</b> — the validation level (DV, OV, EV) as an OID.</li></ul>
 <h3>Fingerprints are not in the certificate</h3>
 <p>A fingerprint is a hash of the whole encoded certificate, worked out by whoever looks at it. SHA-256 is the one to use when searching Censys, Shodan or crt.sh; the public-key hash (SPKI) stays the same when a certificate is renewed with the same key.</p>`,
 cards:[['Which field lists every name a certificate covers?', 'Subject Alternative Name (SAN).'], ['Is the fingerprint stored inside the certificate?', 'No — it is a hash of the encoded certificate, computed by whoever inspects it.'],
  ['Which hash stays the same when a certificate is renewed with the same key?', 'The SPKI (public key) hash, used for key pinning.'], ['Maximum lifetime of a public TLS certificate issued in November 2026?', '200 days (CA/Browser Forum ballot SC-081, from 15 March 2026).']]},

{id:'csr', title:'CSRs: asking for a certificate', lead:'A certificate signing request carries your public key and the names you want, signed with your private key. The private key never leaves your machine.', sample:'csr', cmd:`openssl req -new -newkey rsa:2048 -nodes -keyout site.key -out site.csr \\
  -subj "/CN=www.example.com" -addext "subjectAltName=DNS:www.example.com,DNS:example.com"`,
 body:`<div class="crtg-steps"><div><b>1 · Make a key pair</b><span>On your server. The private key stays there.</span></div><div><b>2 · Make the CSR</b><span>Public key + requested names + extensions, signed with the private key (proof you hold it).</span></div>
  <div><b>3 · The CA validates</b><span>DNS record, HTTP file or email for DV; company checks for OV/EV.</span></div><div><b>4 · The CA issues</b><span>A certificate with your public key, signed by the CA. It may change or drop what you asked for.</span></div></div>
 <h3>What to check in a CSR</h3>
 <ul><li>The signature verifies — the request was not altered.</li><li>The key is strong: RSA 2048+ or ECDSA P-256/P-384.</li><li>Every name is in the SAN extension, and the CN is one of them.</li><li>No secrets: the old “challenge password” attribute is stored in the clear.</li></ul>
 <h3>Why CSRs matter in Active Directory incidents</h3>
 <p>In AD Certificate Services, a template that lets the requester supply their own subject (ESC1) means a normal user can ask for a certificate naming a domain admin, then log in as them with Kerberos PKINIT. Requests and issued certificates with a UPN that does not belong to the requester are the evidence.</p>`,
 cards:[['What proves the requester holds the private key for a CSR?', 'The CSR is signed with that private key.'], ['What is AD CS ESC1?', 'A template that lets the requester set the subject/SAN, so a user can request a certificate as someone else (e.g. a domain admin) and log in with it.'],
  ['Why is a challenge password in a CSR a problem?', 'It is stored in clear text inside the request.']]},

{id:'levels', title:'DV, OV and EV', lead:'How much the CA checked before issuing — readable from the certificate policies extension.', sample:'ov', cmd:'openssl x509 -in cert.pem -noout -ext certificatePolicies',
 body:`<table class="crtg-t"><tr><th>Level</th><th>The CA checked</th><th>Subject shows</th><th>Policy OID</th></tr>
  <tr><td><b>DV</b> domain validated</td><td>Control of the domain only (DNS, HTTP file or email)</td><td>Just the domain</td><td class="mono">2.23.140.1.2.1</td></tr>
  <tr><td><b>OV</b> organisation validated</td><td>The organisation exists and asked for it</td><td>O, L, C</td><td class="mono">2.23.140.1.2.2</td></tr>
  <tr><td><b>EV</b> extended validation</td><td>Stricter legal and operational checks</td><td>O, jurisdiction, registration number</td><td class="mono">2.23.140.1.1</td></tr></table>
 <p>Browsers stopped showing the company name for EV in 2019, so users rarely notice the difference — but investigators can: an OV or EV certificate names a real, checked organisation, which is an attribution lead.</p>
 <p>DV is not a red flag by itself. Most of the web uses free DV certificates (Let’s Encrypt, ZeroSSL, Google Trust Services), and so does most phishing.</p>`,
 cards:[['Where do you read a certificate’s validation level?', 'In the certificate policies extension (2.23.140.1.2.1 DV, .2.2 OV, .1 EV).'], ['Is a DV certificate suspicious?', 'Not by itself — most of the web uses free DV certificates, including phishing sites.']]},

{id:'ct', title:'Certificate Transparency', lead:'Every certificate a public CA issues is published in append-only logs. Anyone can search them — including you.', sample:'ct', cmd:'curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r ".[].name_value" | sort -u',
 body:`<p>Before issuing, the CA sends a <b>precertificate</b> to several logs. Each log returns a <b>signed certificate timestamp (SCT)</b>, a promise to publish it. The SCTs are embedded in the final certificate; Chrome and Safari refuse public certificates without enough of them.</p>
 <h3>Why investigators love it</h3>
 <ul><li><b>Subdomain discovery:</b> every name ever put on a public certificate is listed, including staging, VPN and internal-sounding hosts.</li><li><b>Early warning:</b> phishing domains often appear in CT minutes after registration — brand monitoring watches the stream.</li><li><b>Timeline:</b> the SCT time shows when a certificate was issued, useful when a domain appears in an incident.</li><li><b>Pivots:</b> the same organisation, email or unusual name across certificates links infrastructure.</li></ul>
 <h3>Limits</h3><p>Private CAs and self-signed certificates are never logged. Wildcards hide the actual host names.</p>`,
 cards:[['What is an SCT?', 'A signed certificate timestamp: a CT log’s signed promise to publish the certificate.'], ['Which certificates never appear in CT logs?', 'Self-signed ones and those from private CAs.'], ['How can CT help find a target’s hidden hosts?', 'Search crt.sh for %.domain to list every name that ever appeared on its public certificates.']]},

{id:'revoke', title:'Revocation: CRL and OCSP', lead:'A certificate can be cancelled before it expires — if its key leaks or it was misissued. Checking that is surprisingly unreliable.', sample:'chain', cmd:'openssl ocsp -issuer intermediate.pem -cert leaf.pem -url http://ocsp.example-ca.test -resp_text',
 body:`<ul><li><b>CRL</b> — the CA publishes a signed list of revoked serial numbers at the URL in “CRL distribution points”.</li><li><b>OCSP</b> — ask the CA’s responder about one certificate. Leaks which sites you visit, so many CAs moved away from it: Let’s Encrypt stopped OCSP in 2025 and relies on CRLs.</li>
  <li><b>OCSP stapling</b> — the server fetches the answer and sends it in the handshake. “Must-staple” certificates require that.</li><li><b>Browser-side lists</b> — Firefox (CRLite) and Chrome (CRLSets) push compact revocation data to browsers.</li></ul>
 <p>Most clients <b>soft-fail</b>: if they cannot reach the responder, they carry on. So revoking a stolen key protects less than it sounds — another reason certificates are getting shorter.</p>
 <p>This app cannot check revocation, because that needs a network request. It shows the URLs so you can check them yourself.</p>`,
 cards:[['What does a CRL contain?', 'A CA-signed list of revoked certificate serial numbers.'], ['What is soft-fail revocation checking?', 'If the revocation status cannot be fetched, the client accepts the certificate anyway.'], ['What does OCSP must-staple require?', 'That the server includes a fresh OCSP response in the TLS handshake.']]},

{id:'osint', title:'Certificates in investigations', lead:'One certificate can lead to every server, domain and sibling certificate of an operation.', sample:'phish', cmd:'openssl x509 -in cert.pem -noout -fingerprint -sha256',
 body:`<table class="crtg-t"><tr><th>Start from</th><th>Pivot to</th><th>Where</th></tr>
  <tr><td>SHA-256 fingerprint</td><td>Every IP presenting the same certificate</td><td>Censys, Shodan</td></tr>
  <tr><td>SAN names</td><td>Sibling domains, staging hosts, the operator’s other brands</td><td>crt.sh, passive DNS</td></tr>
  <tr><td>Public key (SPKI hash)</td><td>Certificates renewed with the same key</td><td>Censys</td></tr>
  <tr><td>Subject O / email (OV, self-signed)</td><td>Other certificates with the same details</td><td>crt.sh, Censys</td></tr>
  <tr><td>Issue time (SCT)</td><td>When the infrastructure was set up</td><td>The certificate itself</td></tr></table>
 <h3>Good habits</h3><ul><li>Save the certificate with the case: it may change or vanish tomorrow.</li><li>Record the fingerprint, not just the name — names are reused, fingerprints are unique.</li><li>Shared hosting and CDNs put hundreds of unrelated names on one certificate; do not over-read those.</li></ul>`,
 cards:[['Which value finds every server presenting the same certificate?', 'Its SHA-256 fingerprint, searched in Censys or Shodan.'], ['Why record the fingerprint rather than the name?', 'Names are reused across certificates; a fingerprint identifies exactly one certificate.']]},

{id:'bad', title:'Malicious certificate patterns', lead:'Defaults, impersonation and odd combinations give infrastructure away. None is proof alone; together they make a lead.', sample:'cs', cmd:'openssl x509 -in cert.pem -noout -subject -issuer -dates -serial',
 body:`<ul><li><b>Tool defaults.</b> Cobalt Strike’s out-of-the-box team-server certificate reads <span class="mono">CN=Major Cobalt Strike, O=cobaltstrike, OU=AdvancedPenTesting</span>. openssl’s defaults leave “Internet Widgits Pty Ltd” and “Some-State”.</li>
  <li><b>Self-signed with a famous name</b> — “Microsoft Corporation” in the subject, but nobody signed it.</li><li><b>Lookalike SANs</b> — <span class="mono">microsoftonline-auth.com</span>, <span class="mono">paypal-verify.net</span>: brand words on domains the brand does not own.</li>
  <li><b>Unrelated names together</b> — a login page, a file host and a bare IP on one fresh certificate.</li><li><b>Odd lifetimes</b> — 10–100 years on a self-signed certificate, or validity starting in the future.</li><li><b>Tiny or sequential serials</b> (1, 2, 1000) — public CAs must use at least 64 random bits.</li>
  <li><b>Random-looking names</b> like <span class="mono">www.qjk3xv7a.com</span> issued by <span class="mono">www.pl2kd9.net</span> — the pattern of Tor relays’ TLS certificates.</li><li><b>Code-signing certificates</b> on malware: often stolen from real companies, and later revoked.</li></ul>`,
 cards:[['Default Cobalt Strike certificate subject?', 'CN=Major Cobalt Strike, O=cobaltstrike, OU=AdvancedPenTesting (C=Earth, ST=Cyberspace, L=Somewhere).'], ['Why is a 1-byte serial number suspicious on a CA-issued certificate?', 'Public CAs must use at least 64 bits of randomness; tiny serials point to hand-made certificates.'],
  ['What does “Internet Widgits Pty Ltd” in a certificate tell you?', 'It was made with openssl defaults — by hand, not by a CA.']]},

{id:'openssl', title:'openssl cheatsheet', lead:'The commands you need most, ready to copy.', sample:'phish', cmd:'openssl x509 -in cert.pem -noout -text',
 body:`<table class="crtg-t cmds">
  <tr><td>Read a certificate</td><td class="mono">openssl x509 -in cert.pem -noout -text</td></tr>
  <tr><td>Fetch a site’s chain</td><td class="mono">openssl s_client -connect host:443 -servername host -showcerts &lt;/dev/null</td></tr>
  <tr><td>Just the dates</td><td class="mono">openssl x509 -in cert.pem -noout -dates</td></tr>
  <tr><td>SHA-256 fingerprint</td><td class="mono">openssl x509 -in cert.pem -noout -fingerprint -sha256</td></tr>
  <tr><td>Read a CSR</td><td class="mono">openssl req -in req.csr -noout -text -verify</td></tr>
  <tr><td>Verify a chain</td><td class="mono">openssl verify -CAfile root.pem -untrusted inter.pem leaf.pem</td></tr>
  <tr><td>Key matches certificate?</td><td class="mono">openssl x509 -in cert.pem -noout -pubkey | sha256sum<br>openssl pkey -in key.pem -pubout | sha256sum</td></tr>
  <tr><td>DER → PEM</td><td class="mono">openssl x509 -inform der -in cert.der -out cert.pem</td></tr>
  <tr><td>PKCS#7 bundle → PEM</td><td class="mono">openssl pkcs7 -in bundle.p7b -print_certs -out certs.pem</td></tr>
  <tr><td>Certificates from a .pfx/.p12</td><td class="mono">openssl pkcs12 -in file.pfx -nokeys -out certs.pem</td></tr>
  <tr><td>Windows: list machine certificates</td><td class="mono">certutil -store My</td></tr>
  <tr><td>Windows: dump a certificate</td><td class="mono">certutil -dump cert.cer</td></tr></table>
 <p>Never paste a private key into a website. This app refuses to read private keys and never keeps them.</p>`,
 cards:[['How do you check a private key matches a certificate?', 'Compare the SHA-256 of the certificate’s public key (x509 -pubkey) with the key’s public part (pkey -pubout).'], ['Command to fetch a server’s certificate chain?', 'openssl s_client -connect host:443 -servername host -showcerts']]}
];
