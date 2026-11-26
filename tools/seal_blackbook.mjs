// Seal the Blackbook: encrypt js/data/blackbook-pack.js (never committed) into js/data/blackbook-sealed.js (safe to commit).
//
//   node tools/seal_blackbook.mjs                 asks for the passphrase twice, without showing it
//   BLACKBOOK_PASS=... node tools/seal_blackbook.mjs   for scripts (tests use this with a throwaway passphrase)
//
// gzip, then AES-256-GCM with a key from PBKDF2-SHA256 (600,000 iterations, random 16-byte salt, random 12-byte IV).
// The app asks for the same passphrase and decrypts with WebCrypto in the browser; a wrong passphrase fails the GCM tag.
// Anyone can download the sealed file, so the passphrase is the only protection: use four or more random words.
import { readFileSync, writeFileSync } from 'node:fs';
import { pbkdf2Sync, randomBytes, createCipheriv } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ITER = 600000;

export function seal(json, pass, iter = ITER) {
  const salt = randomBytes(16), iv = randomBytes(12), key = pbkdf2Sync(pass, salt, iter, 32, 'sha256');
  const c = createCipheriv('aes-256-gcm', key, iv), ct = Buffer.concat([c.update(gzipSync(Buffer.from(json, 'utf8'), { level: 9 })), c.final(), c.getAuthTag()]);
  return { v: 1, kdf: 'PBKDF2-SHA256', iter, z: 'gzip', salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64') };
}

function ask(q) {   // read a line from the terminal without echoing it
  return new Promise(res => {
    const out = process.stdout, inp = process.stdin; out.write(q); let s = '';
    if (inp.isTTY) inp.setRawMode(true); inp.resume(); inp.setEncoding('utf8');
    const on = ch => { for (const c of ch) {
      if (c === '\r' || c === '\n') { inp.removeListener('data', on); if (inp.isTTY) inp.setRawMode(false); inp.pause(); out.write('\n'); return res(s); }
      if (c === '\u0003') { out.write('\n'); process.exit(1); }
      if (c === '\u007f' || c === '\b') s = s.slice(0, -1); else s += c; } };
    inp.on('data', on);
  });
}

async function main() {
  const src = readFileSync(path.join(root, 'js', 'data', 'blackbook-pack.js'), 'utf8');
  const json = src.slice(src.indexOf('const BLACKBOOK = ') + 18, src.lastIndexOf(';'));
  JSON.parse(json);   // refuse to seal something broken
  let pass = process.env.BLACKBOOK_PASS;
  if (!pass) {
    pass = await ask('Passphrase for the Blackbook: ');
    if (pass.length < 12) { console.error('Use at least 12 characters — four or more random words is best.'); process.exit(1); }
    if (await ask('Same passphrase again: ') !== pass) { console.error('The two did not match. Nothing written.'); process.exit(1); }
  }
  const out = seal(json, pass);
  writeFileSync(path.join(root, 'js', 'data', 'blackbook-sealed.js'),
    '/* The Blackbook, encrypted (AES-256-GCM, key from a passphrase by PBKDF2-SHA256). Made by tools/seal_blackbook.mjs. */\n' +
    'const BLACKBOOK_SEALED = ' + JSON.stringify(out) + ';\n');
  console.log('Sealed: js/data/blackbook-sealed.js (' + Math.round(out.ct.length * 3 / 4 / 1024) + ' KB). Run python tools/stamp.py, then commit that file.');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
