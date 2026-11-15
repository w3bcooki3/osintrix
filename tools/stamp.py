"""Give every script and stylesheet in index.html an address that changes when the file does.

    python tools/stamp.py

Each reference becomes  file.js?v=<version>-<first 8 hex of the file's SHA-256>.
A browser that cached an earlier copy of a file is made to fetch the new one,
even when two drops share a version number. Run before tools/bundle.py
(bundle.py runs it itself). Python 3, standard library only.
"""
import hashlib, pathlib, re

root = pathlib.Path(__file__).resolve().parent.parent
idx = root / 'index.html'
ver = re.search(r"version:'v([\d.]+)'", (root / 'js' / 'brand.js').read_text(encoding='utf-8')).group(1)

def stamp(m):
    attr, path = m.group(1), m.group(2)
    f = root / path
    if not f.is_file():
        return m.group(0)
    h = hashlib.sha256(f.read_bytes()).hexdigest()[:8]
    return f'{attr}="{path}?v={ver}-{h}"'

html = idx.read_text(encoding='utf-8')
# The Content-Security-Policy meta tag turns off the browser's look-ahead fetching, so without these hints the
# scripts would download one after another. Rebuilt from the script tags each time.
html = re.sub(r'\n<!-- preload:start -->.*?<!-- preload:end -->', '', html, flags=re.S)
scripts = re.findall(r'<script src="(js/[^"?]+\.js)[^"]*"></script>', html)
block = '\n<!-- preload:start -->\n' + '\n'.join(f'<link rel="preload" as="script" href="{s}">' for s in scripts) + '\n<!-- preload:end -->'
html = re.sub(r'(<link rel="stylesheet"[^>]*>\n)(?!<link rel="stylesheet")', lambda m: m.group(1).rstrip('\n') + block + '\n', html, count=1)
new = re.sub(r'(src|href)="((?:js|css)/[^"?]+\.(?:js|css))(?:\?v=[^"]*)?"', stamp, html)
if new != html:
    idx.write_text(new, encoding='utf-8', newline='')
print(str(len(scripts)) + ' scripts preloaded in parallel')
print('index.html  <-  ' + str(len(re.findall(r'\?v=' + re.escape(ver) + '-', new))) + ' files stamped for v' + ver)
