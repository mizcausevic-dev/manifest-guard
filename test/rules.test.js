import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { RULES, parseImage, podSpecOf, evaluateResource, score } from '../src/rules.js';
import { scan, toSarif, documentStartLines, parseManifests, MAX_INPUT_BYTES } from '../src/scan.js';

const insecure = readFileSync(new URL('../examples/insecure.yaml', import.meta.url), 'utf8');
const hardened = readFileSync(new URL('../examples/hardened.yaml', import.meta.url), 'utf8');

test('known-positive control: every rule fires on the insecure example', () => {
  const hit = new Set(scan(insecure).findings.map((f) => f.ruleId));
  for (const r of RULES) assert.ok(hit.has(r.id), `${r.id} did not fire`);
});

test('known-negative control: hardened example is clean and scores 100/A', () => {
  const r = scan(hardened);
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.score, { value: 100, grade: 'A' });
});

test('parseImage handles registries with ports, tags and digests', () => {
  assert.deepEqual(parseImage('nginx'), { repository: 'nginx', tag: null, digest: null });
  assert.deepEqual(parseImage('localhost:5000/app'), { repository: 'localhost:5000/app', tag: null, digest: null });
  assert.equal(parseImage('localhost:5000/app:1.2').tag, '1.2');
  assert.equal(parseImage('app:1@sha256:abc').digest, 'sha256:abc');
});

test('pod spec is found for every workload kind', () => {
  const tpl = { template: { spec: { containers: [] } } };
  for (const kind of ['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job']) assert.ok(podSpecOf({ kind, spec: tpl }));
  assert.ok(podSpecOf({ kind: 'Pod', spec: { containers: [] } }));
  assert.ok(podSpecOf({ kind: 'CronJob', spec: { jobTemplate: { spec: tpl } } }));
  assert.equal(podSpecOf({ kind: 'ConfigMap' }), null);
});

test('pod-level runAsNonRoot satisfies MG007; disabled rules are skipped', () => {
  const pod = { kind: 'Pod', metadata: { name: 'p', namespace: 'x' }, spec: { securityContext: { runAsNonRoot: true }, containers: [{ name: 'c', image: 'a:1' }] } };
  assert.ok(!evaluateResource(pod).some((f) => f.ruleId === 'MG007'));
  assert.ok(!evaluateResource(pod, 0, { disabled: ['MG003'] }).some((f) => f.ruleId === 'MG003'));
});

test('probes are not required for Jobs or init containers', () => {
  const job = { kind: 'Job', metadata: { name: 'j', namespace: 'x' }, spec: { template: { spec: { initContainers: [{ name: 'i', image: 'a:1' }], containers: [{ name: 'c', image: 'a:1' }] } } } };
  assert.ok(!evaluateResource(job).some((f) => f.ruleId === 'MG012'));
});

test('kind: List is expanded and JSON input works', () => {
  const list = JSON.stringify({ kind: 'List', items: [{ kind: 'Service', metadata: { name: 's' }, spec: { type: 'NodePort' } }] });
  const r = scan(list);
  assert.equal(r.resources, 1);
  assert.ok(r.findings.some((f) => f.ruleId === 'MG018'));
});

test('document start lines skip comments and separators', () => {
  assert.deepEqual(documentStartLines('# c\na: 1\n---\n\nb: 2\n'), [2, 5]);
});

test('hostile input: oversize rejected, alias bomb stays bounded and fast', () => {
  assert.throws(() => parseManifests('a: 1\n'.repeat(MAX_INPUT_BYTES / 4)), RangeError);
  let y = 'kind: Pod\nmetadata: {name: bomb, namespace: x}\nanchors:\n  a: &a [{name: x, image: "i:1"}]\n';
  let prev = 'a';
  for (const n of 'bcdefg') { y += `  ${n}: &${n} [${Array(9).fill(`*${prev}`).join(', ')}]\n`; prev = n; }
  y += 'spec:\n  containers: *g\n'; // 9^6 = 531,441 virtual containers
  const t = Date.now();
  const r = scan(y);
  assert.ok(r.findings.length > 0 && r.findings.length <= 200 * RULES.length, `findings ${r.findings.length}`);
  assert.ok(Date.now() - t < 2000, 'alias expansion should not blow up');
});

test('score and grades', () => {
  assert.deepEqual(score([]), { value: 100, grade: 'A' });
  assert.equal(score([{ severity: 'error' }, { severity: 'error' }]).grade, 'C');
});

test('SARIF output is structurally valid 2.1.0', () => {
  const s = toSarif(scan(insecure, { uri: 'examples/insecure.yaml' }));
  assert.equal(s.version, '2.1.0');
  const run = s.runs[0];
  assert.equal(run.tool.driver.rules.length, RULES.length);
  for (const r of run.results) {
    assert.ok(['error', 'warning', 'note'].includes(r.level));
    assert.equal(run.tool.driver.rules[r.ruleIndex].id, r.ruleId);
    assert.ok(r.locations[0].physicalLocation.region.startLine >= 1);
  }
});

test('CLI exit codes: 1 on errors, 0 when clean, 2 on bad usage', () => {
  const cli = new URL('../bin/manifest-guard.mjs', import.meta.url).pathname;
  assert.equal(spawnSync(process.execPath, [cli, 'examples/insecure.yaml']).status, 1);
  assert.equal(spawnSync(process.execPath, [cli, 'examples/hardened.yaml']).status, 0);
  assert.equal(spawnSync(process.execPath, [cli, '--format', 'xml', 'x.yaml']).status, 2);
  const sarif = JSON.parse(execFileSync(process.execPath, [cli, '--format', 'sarif', '--fail-on', 'none', 'examples/insecure.yaml']).toString());
  assert.equal(sarif.version, '2.1.0');
});
