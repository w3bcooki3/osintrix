"""Build the single-file prototype: inlines fonts, styles, Cytoscape and the app scripts."""
import pathlib, json
root = pathlib.Path(__file__).parent; src = root/'src'
shell = (src/'shell.html').read_text(encoding='utf-8')
vendor = (root/'vendor'/'cytoscape.min.js').read_text(encoding='utf-8')
tools = json.loads((src/'tools.json').read_text(encoding='utf-8'))
js = 'const TOOLS_SEED = ' + json.dumps(tools) + ';\nconst QUERY_SEED = ' + (src/'dork_templates.json').read_text(encoding='utf-8') + ';\nconst RULE_SEED = ' + (src/'threat-rules.json').read_text(encoding='utf-8') + ';\n' + '\n'.join((src/f).read_text(encoding='utf-8') for f in
     ['icons.js','engine.js','brand.js','model.js','demo.js','core.js','views.js','graph.js','areas.js','insp.js','intel.js','queries.js','detections.js','notes.js','app.js'])
for part in (vendor, js): assert '</script' not in part.lower()
out = (shell.replace('/*FONTS*/', (src/'fonts.css').read_text(encoding='utf-8')).replace('/*STYLES*/', (src/'styles.css').read_text(encoding='utf-8'))
       .replace('/*VENDOR*/', vendor).replace('/*SCRIPTS*/', js))
(root/'index.html').write_text(out, encoding='utf-8'); print(len(out)//1024, 'KB  ->  index.html')
