// Parsing + orchestration + report formats. Shared by the browser UI and the Node CLI.
import { loadAll } from '../vendor/js-yaml/js-yaml.mjs';
import { RULES, RULE_INDEX, evaluateResource, score, MAX_LIST } from './rules.js';

export const MAX_INPUT_BYTES = 1_000_000;
export const MAX_DOCUMENTS = 500;
export const TOOL = Object.freeze({ name: 'manifest-guard', version: '1.0.0', informationUri: 'https://github.com/mizcausevic-dev/manifest-guard' });

/** 1-based start line of each YAML document (split on "---" separators). */
export function documentStartLines(text) {
  const lines = text.split(/\r?\n/);
  const starts = [];
  let first = null;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (/^---(\s|$)/.test(lines[i]) || /^\.\.\.\s*$/.test(lines[i])) {
      if (first !== null) starts.push(first);
      first = null;
    } else if (t && !t.startsWith('#') && first === null) {
      first = i + 1;
    }
  }
  if (first !== null) starts.push(first);
  return starts;
}

/** Parses multi-document YAML (or JSON). Expands kind: List. Throws on oversize or syntax errors. */
export function parseManifests(text) {
  if (typeof text !== 'string') throw new TypeError('input must be a string');
  if (new TextEncoder().encode(text).length > MAX_INPUT_BYTES) throw new RangeError(`input exceeds ${MAX_INPUT_BYTES} bytes`);
  const docs = loadAll(text).filter((d) => d !== null && d !== undefined);
  if (docs.length > MAX_DOCUMENTS) throw new RangeError(`more than ${MAX_DOCUMENTS} documents`);
  const lines = documentStartLines(text);
  const resources = [];
  docs.forEach((doc, docIndex) => {
    const line = lines[docIndex] ?? 1;
    if (doc && doc.kind === 'List' && Array.isArray(doc.items)) {
      doc.items.slice(0, MAX_LIST).forEach((item) => resources.push({ res: item, docIndex, line }));
    } else {
      resources.push({ res: doc, docIndex, line });
    }
  });
  return resources;
}

export function scan(text, { disabled = [], uri = 'manifest.yaml' } = {}) {
  const resources = parseManifests(text);
  const findings = [];
  for (const { res, docIndex, line } of resources) {
    for (const f of evaluateResource(res, docIndex, { disabled })) findings.push({ ...f, line });
  }
  const order = { error: 0, warning: 1, note: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.line - b.line || a.ruleId.localeCompare(b.ruleId));
  const counts = { error: 0, warning: 0, note: 0 };
  for (const f of findings) counts[f.severity]++;
  return { uri, resources: resources.length, findings, counts, score: score(findings) };
}

/** SARIF 2.1.0 report, accepted by GitHub code scanning (upload-sarif). */
export function toSarif(result) {
  const used = [...new Set(result.findings.map((f) => f.ruleId))];
  const ruleIds = RULES.map((r) => r.id);
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: TOOL.name,
          version: TOOL.version,
          informationUri: TOOL.informationUri,
          rules: RULES.map((r) => ({
            id: r.id,
            name: r.title.replace(/[^A-Za-z0-9]+/g, ' ').trim().replace(/ (\w)/g, (_, ch) => ch.toUpperCase()).replace(/^\w/, (ch) => ch.toUpperCase()),
            shortDescription: { text: r.title },
            fullDescription: { text: r.rationale },
            help: { text: `${r.rationale} Fix: ${r.fix}` },
            defaultConfiguration: { level: r.severity },
          })),
        },
      },
      results: result.findings.map((f) => ({
        ruleId: f.ruleId,
        ruleIndex: ruleIds.indexOf(f.ruleId),
        level: f.severity,
        message: { text: `${f.kind}/${f.name}: ${f.message}. ${RULE_INDEX[f.ruleId].fix}` },
        locations: [{
          physicalLocation: { artifactLocation: { uri: result.uri }, region: { startLine: f.line } },
          logicalLocations: [{ fullyQualifiedName: `${f.kind}/${f.name}${f.container ? `/${f.container}` : ''}:${f.field}`, kind: 'resource' }],
        }],
      })),
      properties: { usedRules: used },
    }],
  };
}

export function toText(result) {
  const out = [`${result.uri}: ${result.resources} resource(s), ${result.counts.error} error(s), ${result.counts.warning} warning(s), ${result.counts.note} note(s), score ${result.score.value} (${result.score.grade})`];
  for (const f of result.findings) {
    out.push(`  ${f.severity.padEnd(7)} ${f.ruleId} line ${f.line} ${f.kind}/${f.name}${f.container ? ` [${f.container}]` : ''}: ${f.message}`);
  }
  return out.join('\n');
}
