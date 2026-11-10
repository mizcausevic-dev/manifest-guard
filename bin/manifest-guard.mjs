#!/usr/bin/env node
// manifest-guard CLI: scan Kubernetes manifests in CI.
// Usage: manifest-guard [--format text|json|sarif] [--fail-on error|warning|note|none] [--disable MG002,MG008] <file...>
import { readFileSync } from 'node:fs';
import { scan, toSarif, toText } from '../src/scan.js';

const USAGE = 'usage: manifest-guard [--format text|json|sarif] [--fail-on error|warning|note|none] [--disable IDS] <file.yaml...>';
const args = process.argv.slice(2);
let format = 'text', failOn = 'error', disabled = [];
const files = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--format') format = args[++i];
  else if (a === '--fail-on') failOn = args[++i];
  else if (a === '--disable') disabled = String(args[++i] ?? '').split(',').filter(Boolean);
  else if (a === '-h' || a === '--help') { console.log(USAGE); process.exit(0); }
  else if (a.startsWith('-')) { console.error(`unknown option ${a}\n${USAGE}`); process.exit(2); }
  else files.push(a);
}
if (!files.length || !['text', 'json', 'sarif'].includes(format) || !['error', 'warning', 'note', 'none'].includes(failOn)) {
  console.error(USAGE);
  process.exit(2);
}

const results = [];
for (const file of files) {
  try {
    results.push(scan(readFileSync(file, 'utf8'), { uri: file, disabled }));
  } catch (e) {
    console.error(`${file}: ${e.message}`);
    process.exit(2);
  }
}

if (format === 'text') console.log(results.map(toText).join('\n'));
else if (format === 'json') console.log(JSON.stringify(results, null, 2));
else {
  const sarifs = results.map(toSarif);
  const merged = { ...sarifs[0], runs: [{ ...sarifs[0].runs[0], results: sarifs.flatMap((s) => s.runs[0].results) }] };
  console.log(JSON.stringify(merged, null, 2));
}

const rank = { error: 0, warning: 1, note: 2 };
const failing = failOn !== 'none' && results.some((r) => r.findings.some((f) => rank[f.severity] <= rank[failOn]));
process.exit(failing ? 1 : 0);
