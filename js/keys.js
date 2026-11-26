/* ==========================================================================
   Keyboard shortcuts — one list, shown in Help and by pressing ? anywhere
   (except while typing).
   ========================================================================== */
const KBD_LIST = [
  ['Everywhere', [[['Ctrl', 'K'], 'Search everything — cases, indicators, tools, notes, actions'], [['/'], 'Search everything (or this page, where it has its own search)'], [['N'], 'Capture evidence'], [['E'], 'Add a vault entry'],
    [['?'], 'This list'], [['Esc'], 'Close a panel, dialog or menu'], [['←', '→'], 'Move between tabs, and open the one reached'], [['1', '–', '8'], 'Switch case tabs'], [['Ctrl', 'Enter'], 'Save a capture or note']]],
  ['Search (Ctrl K)', [[['↑', '↓'], 'Move through the results'], [['Enter'], 'Open the result'], [['Tab'], 'Finish a filter being typed (verdict:, type:, tag:, is:, case:) — or the next scope'], [['Alt', '1–9'], 'Act on the highlighted result: copy, watch, open a lookup…']]],
  ['Vault and graph', [[['Shift', 'click'], 'Select a range of entries'], [['Esc'], 'Clear the selection'], [['Shift', 'F10'], 'Graph menu for the selected node'], [['Right-click'], 'Copy, defang, look up or mask any indicator or selected text — Shift+right-click for the browser’s own menu']]],
  ['Notes', [[['@'], 'Link a vault entry — ↑ ↓ to pick, Enter or Tab to insert']]],
  ['Patterns — Build a pattern', [[['↑', '↓'], 'Move between lines (also j and k)'], [['M'], 'Next line the pattern misses'], [['/'], 'Edit the pattern'], [['Ctrl', 'Z'], 'Undo (Ctrl+Shift+Z redo)']]],
  ['Detections', [[['Ctrl', 'S'], 'Save the rule you are editing']]],
];
const keysHtml = () => KBD_LIST.map(([g, L]) => `<div class="keys-g"><h3>${esc(g)}</h3>${L.map(([k, t]) => `<div class="keys-r"><span class="keys-k">${k.map(x => /^[–]$/.test(x) ? x : `<kbd>${esc(x)}</kbd>`).join(' ')}</span><span>${esc(t)}</span></div>`).join('')}</div>`).join('');
function keysDlg(){ openDlg(dhead('Keyboard shortcuts') + `<div class="in keys">${keysHtml()}</div><footer><button class="btn ghost" data-act="keysHelp">More in Help</button><button class="btn" data-act="dclose">Close</button></footer>`, true); }
document.addEventListener('keydown', ev => {
  if(ev.key !== '?' || ev.ctrlKey || ev.metaKey || ev.altKey) return;
  const t = ev.target; if(t && t.closest && t.closest('input, textarea, select, [contenteditable], .cm-editor')) return;
  if(!$('scrim') || !$('scrim').hidden || (typeof S !== 'undefined' && S.open)) return;   /* not over a dialog or the search */
  ev.preventDefault(); keysDlg(); });
const KEYS_ACTS = {keysHelp:() => { closeDlg(); go('#/help'); }, keysOpen:() => keysDlg()};
