# OSINTrix v1.18 — Trust and scale

## Commit summary
v1.18: tamper-evident audit log, browser-held signing key, chunked saves, fast large graphs

## Description
Fixes the three items left open after v1.17.

**Audit log and custody reports can't be forged**
- Audit entries are now sealed with an HMAC key the browser keeps in IndexedDB as a non-extractable CryptoKey. Editing, removing or reordering entries in the saved JSON is detected, and so is stripping the seal to fall back to plain hashes (the index of the first sealed entry is recorded).
- The ECDSA custody signing key is non-extractable too. It is no longer stored in the workspace or in backups; old keys are migrated on first start.
- Custody reports show the signer's key fingerprint. A report signed by an untrusted key is flagged even when its signature is valid, and a colleague's key can be trusted by its fingerprint.

**Large cases save quickly**
- Workspaces with 2,000+ records are saved in 500-record chunks in one IndexedDB transaction, and only changed chunks are written.
- 20,000 records: about 45 ms per save (was about 135 ms) and about 350 KB written (was about 14 MB).
- A missing chunk on load sends the user to the recovery screen instead of loading partial data.

**Big graphs no longer freeze**
- A spatial-hash force layout places graphs over 300 nodes.
- Edges and labels hide while panning or zooming.
- Cluster styling isn't cleared when it was never applied.
- A 2,000-node board opens in about 2 s (was about 41 s).

**Tests**
- 24/24 Playwright tests pass.
- New tests: audit and custody forgery, chunked saves plus a 2,000-node board.

## Files changed
CHANGELOG.md, css/design.css, index.html, package.json, tests/app.spec.js,
js/app.js, js/brand.js, js/core.js, js/data/changelog.js, js/graph.js,
js/relate.js, js/safety.js, js/security.js

## Still open
- If the browser's own storage is wiped, the audit key goes with it: the log can no longer be re-verified locally (exported signed reports still verify by fingerprint).
- Encrypted workspaces (passphrase on) still save in one piece, so they stay slower at very large sizes.
- Boards of 5,000+ nodes are usable but heavy; for those, filters or the entities view work better than the full board.
