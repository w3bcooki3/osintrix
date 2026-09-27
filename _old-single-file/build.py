"""Build OSINTrix into one self-contained index.html.

Inlines the fonts, styles, vendored libraries (Cytoscape.js, jsQR, the IEEE OUI
vendor list) and the app scripts. Python 3, standard library only.
    python build.py
"""
import pathlib, json
root = pathlib.Path(__file__).parent; src = root / 'src'; ven = root / 'vendor'
read = lambda p: p.read_text(encoding='utf-8')
SCRIPTS = ['icons.js', 'engine.js', 'brand.js', 'model.js', 'demo.js', 'core.js', 'views.js', 'graph.js', 'areas.js', 'insp.js', 'intel.js',
           'queries.js', 'detections.js', 'notes.js', 'playbooks.js', 'extras.js', 'lab.js', 'kit.js', 'search.js', 'safety.js', 'tl.js', 'report.js', 'app.js']
vendor = read(ven / 'cytoscape.min.js') + '\n' + read(ven / 'jsqr.min.js') + '\nconst OUI_B64 = "' + read(ven / 'oui.b64').strip() + '";'
js = ('const TOOLS_SEED = ' + json.dumps(json.loads(read(src / 'tools.json'))) + ';\nconst QUERY_SEED = ' + read(src / 'dork_templates.json') +
      ';\nconst RULE_SEED = ' + read(src / 'threat-rules.json') + ';\n' + '\n'.join(read(src / f) for f in SCRIPTS))
for part in (vendor, js): assert '</script' not in part.lower()
out = (read(src / 'shell.html').replace('/*FONTS*/', read(src / 'fonts.css')).replace('/*STYLES*/', read(src / 'styles.css'))
       .replace('/*VENDOR*/', vendor).replace('/*SCRIPTS*/', js))
(root / 'index.html').write_text(out, encoding='utf-8')
print(len(out) // 1024, 'KB  ->  index.html')
