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

html = re.sub(r'<link rel="stylesheet" href="([^"]+)">', lambda m: css(m.group(1)), html)
html = re.sub(r'<script src="([^"]+)"></script>', lambda m: js(m.group(1)), html)
# everything is inline now, so the policy allows inline code and data: fonts instead of files
html = re.sub(r'content="default-src[^"]*"', "content=\"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; "
              "connect-src https://api.rss2json.com; form-action 'none'; base-uri 'none'\"", html)
out = root / 'dist' / 'osintrix-offline.html'; out.parent.mkdir(exist_ok=True); out.write_text(html, encoding='utf-8')
print(len(html) // 1024, 'KB  ->', out.relative_to(root))
