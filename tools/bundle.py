"""Optional: pack OSINTrix into ONE self-contained HTML file (for emailing, USB sticks, air-gapped use).

The app itself is the multi-file site in this folder (index.html + css/ + js/ + fonts/) and needs no build.
This script only produces an extra convenience copy:
    python tools/bundle.py        ->  dist/osintrix-offline.html
Python 3, standard library only.
"""
import base64, pathlib, re
root = pathlib.Path(__file__).resolve().parent.parent
html = (root / 'index.html').read_text(encoding='utf-8')

def css(href):
    text = (root / href).read_text(encoding='utf-8')
    def font(m):
        f = (root / href).parent / m.group(1)
        return 'url(data:font/woff2;base64,' + base64.b64encode(f.read_bytes()).decode() + ')'
    return '<style>' + re.sub(r'url\("?([^")]+\.woff2)"?\)', font, text) + '</style>'

def js(src):
    code = (root / src).read_text(encoding='utf-8')
    assert '</script' not in code.lower(), src
    return '<script>' + code + '</script>'

html = re.sub(r'<link rel="stylesheet" href="([^"]+)">', lambda m: css(m.group(1).split('?')[0]), html)
html = re.sub(r'<script src="([^"]+)"></script>', lambda m: js(m.group(1).split('?')[0]), html)
# welcome-screen pictures become data: URIs so the one-file copy has no loose files
for n in ('dashboard-dark', 'dashboard-light', 'graph-dark', 'graph-light', 'phone-dark', 'phone-light', 'timeline-dark', 'timeline-light'):
    f = root / 'assets' / 'welcome' / (n + '.jpg')
    if f.exists(): html = html.replace('assets/welcome/' + n + '.jpg', 'data:image/jpeg;base64,' + base64.b64encode(f.read_bytes()).decode())
# engines loaded on demand (the SQLite viewer) ride along as inert text and are started from it when needed
LAZY = ['js/vendor/sql-wasm.js', 'js/vendor/sql-wasm-b64.js']
i = html.rfind('</body>')   # the page's own closing tag, not one inside a script's text
html = html[:i] + ''.join('<script type="text/plain" id="lazy:' + p + '">' + (root / p).read_text(encoding='utf-8') + '</script>' for p in LAZY) + html[i:]
# The policy allows exactly the scripts in this file, by hash: no 'unsafe-inline', so markup that
# ends up in the page (an imported name, a saved web page) can never run as script.
import hashlib
def sha(code): return "'sha256-" + base64.b64encode(hashlib.sha256(code.encode('utf-8')).digest()).decode() + "'"
hashes = [sha(m.group(1)) for m in re.finditer(r'<script>(.*?)</script>', html, flags=re.S)]
hashes += [sha((root / p).read_text(encoding='utf-8')) for p in LAZY]          # started later from their text
csp = ("default-src 'none'; script-src " + ' '.join(dict.fromkeys(hashes)) + " 'wasm-unsafe-eval'; style-src 'unsafe-inline'; "
       "img-src data: blob:; font-src data:; "
       "connect-src https://api.rss2json.com; form-action 'none'; base-uri 'none'; object-src 'none'")
html = re.sub(r'content="default-src[^"]*"', lambda m: 'content="' + csp + '"', html, count=1)
out = root / 'dist' / 'osintrix-offline.html'; out.parent.mkdir(exist_ok=True); out.write_text(html, encoding='utf-8')
print(len(html) // 1024, 'KB  ->', out.relative_to(root))
