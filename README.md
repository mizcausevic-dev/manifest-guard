# Manifest Guard

[![CI](https://github.com/mizcausevic-dev/manifest-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/mizcausevic-dev/manifest-guard/actions/workflows/ci.yml)
[![Pages](https://github.com/mizcausevic-dev/manifest-guard/actions/workflows/pages.yml/badge.svg)](https://mizcausevic-dev.github.io/manifest-guard/)
![Install steps: 0](https://img.shields.io/badge/install%20steps-0-66fcf1)
![License: MIT](https://img.shields.io/badge/license-MIT-45a29e)

**Live demo: https://mizcausevic-dev.github.io/manifest-guard/**

Policy-as-code for Kubernetes manifests. Paste YAML in the browser, or run the CLI in CI. 18 rules catch the misconfigurations behind real container escapes, leaked credentials and avoidable outages. Output comes as text, JSON or **SARIF 2.1.0** for GitHub code scanning.

## Why this exists

Admission controllers catch problems at deploy time, which is too late for a fast review loop. Manifest Guard puts the same guardrails at the pull request and in a page any engineer can open. There's nothing to install, and nothing leaves the browser.

## Rules

| ID | Severity | Check |
|---|---|---|
| MG001 | error | Image uses `:latest` or no tag |
| MG002 | note | Image not pinned by digest |
| MG003 | warning | Missing memory limit |
| MG004 | warning | Missing CPU/memory requests |
| MG005 | error | Privileged container |
| MG006 | warning | `allowPrivilegeEscalation` not false |
| MG007 | warning | May run as root (pod- and container-level context both honored) |
| MG008 | note | Writable root filesystem |
| MG009 | error | `hostNetwork` / `hostPID` / `hostIPC` |
| MG010 | error | Dangerous capabilities added (`SYS_ADMIN`, `NET_ADMIN`, `ALL`, ...) |
| MG011 | note | Capabilities not dropped |
| MG012 | warning | Missing readiness/liveness probes (skipped for Jobs and init containers) |
| MG013 | warning | `hostPath` volumes |
| MG014 | error | Secret-looking env var with a literal value |
| MG015 | note | Single replica |
| MG016 | note | Service account token auto-mounted |
| MG017 | note | Default or missing namespace |
| MG018 | note | Service exposed via NodePort/LoadBalancer |

Covers Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob and Service, plus `kind: List` and multi-document YAML.

## CLI

```bash
node bin/manifest-guard.mjs k8s/*.yaml                                   # text report, exit 1 on errors
node bin/manifest-guard.mjs --format sarif --fail-on none k8s/*.yaml > results.sarif
node bin/manifest-guard.mjs --disable MG002,MG008 --fail-on warning deploy.yaml
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage or parse error.

GitHub Actions with code scanning:

```yaml
- run: node bin/manifest-guard.mjs --format sarif --fail-on none k8s/*.yaml > manifest-guard.sarif
- uses: github/codeql-action/upload-sarif@v4
  with: { sarif_file: manifest-guard.sarif }
```

## Architecture

```
bin/manifest-guard.mjs ─┐
                        ├─► src/scan.js   parse (js-yaml), bounds, line mapping, SARIF/JSON/text
index.html + app.js  ───┘        │
                                 ▼
                           src/rules.js   18 pure rule functions, no I/O
```

- **One engine, two surfaces.** The browser and the CLI import the same modules, so a rule behaves the same everywhere.
- **Known-positive and known-negative controls.** `examples/insecure.yaml` must trigger every rule, and `examples/hardened.yaml` must trigger none. Both are asserted in unit tests and again in CI by running the CLI and checking its exit codes.
- **Hostile-input hardening.** Input is capped at 1 MB and 500 documents. List iteration is bounded, so a YAML alias bomb (531,441 virtual containers) finishes in milliseconds, and a test covers it. The page sets a strict CSP and renders output with `textContent` only.
- **Supply chain.** The only third-party code is js-yaml 5.5.0, vendored with recorded integrity hashes ([PROVENANCE](vendor/js-yaml/PROVENANCE.md)). There's no CDN and no `npm install`.

## Run locally

```bash
git clone https://github.com/mizcausevic-dev/manifest-guard
cd manifest-guard
npm test
python3 -m http.server 8080   # open http://localhost:8080
```

## Limits

This is static analysis of manifests. It doesn't see admission-time mutations, Helm/Kustomize rendering (render first, then scan), or runtime state. Rule severities are opinionated defaults, so tune them with `--disable`.

## License

MIT © 2026 Mirza Causevic / Kinetic Gain LLC. js-yaml is © Vitaly Puzrin, MIT.
