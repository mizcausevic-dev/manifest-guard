import { scan, toSarif, MAX_INPUT_BYTES } from './scan.js';
import { RULES, RULE_INDEX } from './rules.js';

const $ = (id) => document.getElementById(id);
let last = null;
let timer = null;

function el(tag, attrs = {}, text) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

const SEV_CLASS = { error: 'danger', warning: 'warn', note: 'info' };

function renderTiles(r) {
  const tiles = $('tiles');
  tiles.replaceChildren();
  const g = el('div', { class: 'tile' });
  g.append(el('div', { class: 'k' }, 'Grade'), el('div', { class: `grade ${r.score.grade}` }, r.score.grade), el('div', { class: 's' }, `score ${r.score.value}/100`));
  tiles.append(g);
  for (const [k, v, s] of [['Errors', r.counts.error, 'block merge'], ['Warnings', r.counts.warning, 'fix soon'], ['Notes', r.counts.note, `${r.resources} resource(s) scanned`]]) {
    const t = el('div', { class: 'tile' });
    t.append(el('div', { class: 'k' }, k), el('div', { class: 'v' }, String(v)), el('div', { class: 's' }, s));
    tiles.append(t);
  }
}

function renderFindings() {
  const body = $('findings').querySelector('tbody');
  body.replaceChildren();
  if (!last) return;
  const show = new Set([...document.querySelectorAll('[data-sev]')].filter((c) => c.checked).map((c) => c.dataset.sev));
  const rows = last.findings.filter((f) => show.has(f.severity));
  if (!rows.length) {
    const tr = el('tr');
    tr.append(el('td', { colspan: '5' }, last.findings.length ? 'No findings match the filter.' : 'No findings. This manifest passes every rule.'));
    body.append(tr);
    return;
  }
  for (const f of rows) {
    const tr = el('tr');
    const sev = el('td');
    sev.append(el('span', { class: `pill ${SEV_CLASS[f.severity]}` }, f.severity));
    const msg = el('td');
    msg.append(el('div', {}, f.message), el('div', { class: 'finding-fix' }, `Fix: ${RULE_INDEX[f.ruleId].fix}`));
    tr.append(sev, el('td', {}, f.ruleId), el('td', { class: 'num' }, String(f.line)), el('td', {}, `${f.kind}/${f.name}${f.container ? ` · ${f.container}` : ''}`), msg);
    body.append(tr);
  }
}

function run() {
  const err = $('err');
  err.textContent = '';
  try {
    last = scan($('yaml').value, { uri: 'manifest.yaml' });
    renderTiles(last);
    renderFindings();
  } catch (e) {
    last = null;
    err.textContent = `Could not parse: ${String(e.message).split('\n')[0]}`;
    $('tiles').replaceChildren();
    $('findings').querySelector('tbody').replaceChildren();
  }
}

function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = el('a', { href: url, download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function loadExample(name) {
  if (name === 'blank') { $('yaml').value = ''; run(); return; }
  try {
    const res = await fetch(`examples/${name}.yaml`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    $('yaml').value = await res.text();
  } catch (e) {
    $('err').textContent = `Could not load example (${e.message}). Serve the folder over HTTP.`;
    return;
  }
  run();
}

function renderCatalog() {
  const box = $('catalog');
  for (const r of RULES) {
    const d = el('details', { class: 'rule' });
    const s = el('summary');
    s.append(el('span', { class: `pill ${SEV_CLASS[r.severity]}` }, r.severity), document.createTextNode(` ${r.id} · ${r.title}`));
    d.append(s, el('p', {}, `Why: ${r.rationale}`), el('p', {}, `Fix: ${r.fix}`));
    box.append(d);
  }
}

function init() {
  renderCatalog();
  $('yaml').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(run, 200); });
  $('example').addEventListener('change', (e) => loadExample(e.target.value));
  $('file').addEventListener('change', (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > MAX_INPUT_BYTES) { $('err').textContent = `File is larger than ${MAX_INPUT_BYTES} bytes.`; return; }
    const reader = new FileReader();
    reader.onload = () => { $('yaml').value = String(reader.result); run(); };
    reader.readAsText(f);
  });
  document.querySelectorAll('[data-sev]').forEach((c) => c.addEventListener('change', renderFindings));
  $('dl-sarif').addEventListener('click', () => last && download('manifest-guard.sarif', JSON.stringify(toSarif(last), null, 2), 'application/sarif+json'));
  $('dl-json').addEventListener('click', () => last && download('manifest-guard.json', JSON.stringify(last, null, 2), 'application/json'));
  loadExample('insecure');
}

init();
