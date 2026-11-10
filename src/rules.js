// Policy-as-code rules for Kubernetes workload manifests. Pure functions, no DOM, no I/O.
// Each rule receives a parsed resource plus helpers and returns findings.

export const SEVERITY_WEIGHT = Object.freeze({ error: 15, warning: 6, note: 2 });

const WORKLOAD_KINDS = new Set(['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'CronJob', 'ReplicationController']);
const SECRETY_ENV = /(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?)/i;
const DANGEROUS_CAPS = new Set(['ALL', 'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'DAC_READ_SEARCH', 'BPF']);

/** Returns the pod spec and its JSON path for any workload kind, or null. */
export function podSpecOf(res) {
  if (!res || typeof res !== 'object') return null;
  switch (res.kind) {
    case 'Pod':
      return res.spec ? { spec: res.spec, path: '/spec' } : null;
    case 'CronJob': {
      const s = res.spec?.jobTemplate?.spec?.template?.spec;
      return s ? { spec: s, path: '/spec/jobTemplate/spec/template/spec' } : null;
    }
    default: {
      if (!WORKLOAD_KINDS.has(res.kind)) return null;
      const s = res.spec?.template?.spec;
      return s ? { spec: s, path: '/spec/template/spec' } : null;
    }
  }
}

function containersOf(pod) {
  const out = [];
  for (const [field, items] of [['initContainers', pod.spec.initContainers], ['containers', pod.spec.containers]]) {
    if (!Array.isArray(items)) continue;
    items.slice(0, MAX_LIST).forEach((c, i) => {
      if (c && typeof c === 'object') out.push({ c, path: `${pod.path}/${field}/${i}`, init: field === 'initContainers', name: String(c.name ?? `${field}[${i}]`) });
    });
  }
  return out;
}

/** Parses an image reference into repository, tag and digest. */
export function parseImage(image) {
  const s = String(image ?? '');
  const at = s.indexOf('@');
  const digest = at >= 0 ? s.slice(at + 1) : null;
  const ref = at >= 0 ? s.slice(0, at) : s;
  const lastSlash = ref.lastIndexOf('/');
  const colon = ref.lastIndexOf(':');
  const tag = colon > lastSlash ? ref.slice(colon + 1) : null;
  return { repository: colon > lastSlash ? ref.slice(0, colon) : ref, tag, digest };
}

// Bounded iteration: YAML aliases can make arrays appear enormous; never walk more than this.
export const MAX_LIST = 200;
const list = (x) => (Array.isArray(x) ? x.slice(0, MAX_LIST) : []);

const effective = (c, pod, key) => c.securityContext?.[key] ?? pod.spec.securityContext?.[key];

export const RULES = [
  {
    id: 'MG001', severity: 'error', title: 'Image uses :latest or no tag',
    rationale: 'Mutable tags make deployments non-reproducible and rollbacks unreliable.',
    fix: 'Pin an immutable version tag, ideally plus a digest.',
    containers: true,
    check: ({ c }) => {
      const { tag, digest } = parseImage(c.image);
      if (digest) return null;
      if (!tag || tag === 'latest') return { message: `image "${c.image}" is ${tag ? 'tagged :latest' : 'untagged (defaults to :latest)'}`, field: 'image' };
      return null;
    },
  },
  {
    id: 'MG002', severity: 'note', title: 'Image not pinned by digest',
    rationale: 'Tags can be re-pushed. A digest guarantees the bytes you scanned are the bytes you run.',
    fix: 'Reference images as repo:tag@sha256:<digest>.',
    containers: true,
    check: ({ c }) => (parseImage(c.image).digest ? null : { message: `image "${c.image}" is not pinned by digest`, field: 'image' }),
  },
  {
    id: 'MG003', severity: 'warning', title: 'Missing memory limit',
    rationale: 'Without a memory limit one container can exhaust node memory and trigger evictions of neighbours.',
    fix: 'Set resources.limits.memory.',
    containers: true,
    check: ({ c }) => (c.resources?.limits?.memory ? null : { message: `container "${c.name}" has no memory limit`, field: 'resources.limits.memory' }),
  },
  {
    id: 'MG004', severity: 'warning', title: 'Missing CPU/memory requests',
    rationale: 'Requests drive scheduling. Without them the scheduler over-packs nodes and QoS drops to BestEffort.',
    fix: 'Set resources.requests.cpu and resources.requests.memory.',
    containers: true,
    check: ({ c }) => {
      const missing = ['cpu', 'memory'].filter((k) => !c.resources?.requests?.[k]);
      return missing.length ? { message: `container "${c.name}" has no ${missing.join('/')} request`, field: 'resources.requests' } : null;
    },
  },
  {
    id: 'MG005', severity: 'error', title: 'Privileged container',
    rationale: 'privileged: true gives the container effectively root on the host.',
    fix: 'Remove privileged, grant only the specific capabilities needed.',
    containers: true,
    check: ({ c }) => (c.securityContext?.privileged === true ? { message: `container "${c.name}" runs privileged`, field: 'securityContext.privileged' } : null),
  },
  {
    id: 'MG006', severity: 'warning', title: 'Privilege escalation not disabled',
    rationale: 'Without allowPrivilegeEscalation: false, setuid binaries can gain more privileges than the parent process.',
    fix: 'Set securityContext.allowPrivilegeEscalation: false.',
    containers: true,
    check: ({ c }) => (c.securityContext?.allowPrivilegeEscalation === false ? null : { message: `container "${c.name}" does not set allowPrivilegeEscalation: false`, field: 'securityContext.allowPrivilegeEscalation' }),
  },
  {
    id: 'MG007', severity: 'warning', title: 'May run as root',
    rationale: 'A container breakout from a root process starts with far more privilege.',
    fix: 'Set runAsNonRoot: true (pod or container securityContext) and a non-zero runAsUser.',
    containers: true,
    check: ({ c, pod }) => {
      if (effective(c, pod, 'runAsUser') === 0) return { message: `container "${c.name}" explicitly runs as UID 0`, field: 'securityContext.runAsUser' };
      return effective(c, pod, 'runAsNonRoot') === true ? null : { message: `container "${c.name}" does not enforce runAsNonRoot`, field: 'securityContext.runAsNonRoot' };
    },
  },
  {
    id: 'MG008', severity: 'note', title: 'Writable root filesystem',
    rationale: 'A read-only root filesystem blocks a large class of persistence and tampering techniques.',
    fix: 'Set securityContext.readOnlyRootFilesystem: true and mount emptyDir for scratch paths.',
    containers: true,
    check: ({ c }) => (c.securityContext?.readOnlyRootFilesystem === true ? null : { message: `container "${c.name}" has a writable root filesystem`, field: 'securityContext.readOnlyRootFilesystem' }),
  },
  {
    id: 'MG009', severity: 'error', title: 'Host namespace sharing',
    rationale: 'hostNetwork, hostPID and hostIPC break the isolation boundary between pod and node.',
    fix: 'Remove hostNetwork/hostPID/hostIPC unless this is a vetted node agent.',
    pod: true,
    check: ({ pod }) => {
      const on = ['hostNetwork', 'hostPID', 'hostIPC'].filter((k) => pod.spec[k] === true);
      return on.length ? { message: `pod shares host namespaces: ${on.join(', ')}`, field: on[0] } : null;
    },
  },
  {
    id: 'MG010', severity: 'error', title: 'Dangerous Linux capability added',
    rationale: 'Capabilities such as SYS_ADMIN or NET_ADMIN are close to full root.',
    fix: 'Drop ALL and add back only narrowly scoped capabilities such as NET_BIND_SERVICE.',
    containers: true,
    check: ({ c }) => {
      const add = list(c.securityContext?.capabilities?.add).map(String);
      const bad = add.filter((cap) => DANGEROUS_CAPS.has(cap.toUpperCase().replace(/^CAP_/, '')));
      return bad.length ? { message: `container "${c.name}" adds ${bad.join(', ')}`, field: 'securityContext.capabilities.add' } : null;
    },
  },
  {
    id: 'MG011', severity: 'note', title: 'Capabilities not dropped',
    rationale: 'Container runtimes grant a default capability set. Dropping ALL is the hardened baseline.',
    fix: 'Set securityContext.capabilities.drop: ["ALL"].',
    containers: true,
    check: ({ c }) => {
      const drop = list(c.securityContext?.capabilities?.drop).map((x) => String(x).toUpperCase());
      return drop.includes('ALL') ? null : { message: `container "${c.name}" does not drop ALL capabilities`, field: 'securityContext.capabilities.drop' };
    },
  },
  {
    id: 'MG012', severity: 'warning', title: 'Missing health probes',
    rationale: 'Without readiness probes traffic hits pods that are not ready. Without liveness probes hung processes are never restarted.',
    fix: 'Add readinessProbe and livenessProbe (or startupProbe for slow starters).',
    containers: true,
    check: ({ c, init, res }) => {
      if (init || res.kind === 'Job' || res.kind === 'CronJob') return null;
      const missing = ['readinessProbe', 'livenessProbe'].filter((k) => !c[k]);
      return missing.length ? { message: `container "${c.name}" has no ${missing.join(' or ')}`, field: missing[0] } : null;
    },
  },
  {
    id: 'MG013', severity: 'warning', title: 'hostPath volume',
    rationale: 'hostPath mounts expose the node filesystem and are a common container-escape path.',
    fix: 'Use PersistentVolumeClaims, configMaps, secrets or emptyDir.',
    pod: true,
    check: ({ pod }) => {
      const hp = list(pod.spec.volumes).filter((v) => v && v.hostPath).map((v) => `${v.name} -> ${v.hostPath.path}`);
      return hp.length ? { message: `hostPath volumes: ${hp.join(', ')}`, field: 'volumes' } : null;
    },
  },
  {
    id: 'MG014', severity: 'error', title: 'Secret value in plain env var',
    rationale: 'Literal secrets in manifests leak through Git history, kubectl describe and CI logs.',
    fix: 'Use valueFrom.secretKeyRef or an external secrets operator.',
    containers: true,
    check: ({ c }) => {
      const hits = list(c.env).filter((e) => e && SECRETY_ENV.test(String(e.name)) && typeof e.value === 'string' && e.value.length > 0).map((e) => e.name);
      return hits.length ? { message: `container "${c.name}" sets ${hits.join(', ')} as a literal value`, field: 'env' } : null;
    },
  },
  {
    id: 'MG015', severity: 'note', title: 'Single replica',
    rationale: 'One replica means every node drain, deploy or crash is an outage.',
    fix: 'Run at least 2 replicas with a PodDisruptionBudget.',
    resource: true,
    check: ({ res }) => {
      if (!['Deployment', 'StatefulSet', 'ReplicaSet'].includes(res.kind)) return null;
      const r = res.spec?.replicas ?? 1;
      return r < 2 ? { message: `${res.kind} runs ${r} replica${r === 1 ? '' : 's'}`, field: 'spec.replicas' } : null;
    },
  },
  {
    id: 'MG016', severity: 'note', title: 'Service account token auto-mounted',
    rationale: 'Most workloads never call the Kubernetes API. A mounted token is free lateral movement.',
    fix: 'Set automountServiceAccountToken: false unless the pod needs API access.',
    pod: true,
    check: ({ pod }) => (pod.spec.automountServiceAccountToken === false ? null : { message: 'service account token is auto-mounted', field: 'automountServiceAccountToken' }),
  },
  {
    id: 'MG017', severity: 'note', title: 'Default or missing namespace',
    rationale: 'The default namespace usually has the loosest policies and mixes unrelated workloads.',
    fix: 'Set metadata.namespace to a dedicated namespace.',
    resource: true,
    check: ({ res }) => {
      if (res.kind === 'Namespace') return null;
      const ns = res.metadata?.namespace;
      return !ns || ns === 'default' ? { message: `${res.kind} is in the ${ns ? '"default"' : 'implicit default'} namespace`, field: 'metadata.namespace' } : null;
    },
  },
  {
    id: 'MG018', severity: 'note', title: 'Service exposed via NodePort/LoadBalancer',
    rationale: 'Direct exposure bypasses the shared ingress layer (WAF, TLS policy, rate limits).',
    fix: 'Prefer ClusterIP behind an Ingress or Gateway unless direct exposure is intended.',
    resource: true,
    check: ({ res }) => (res.kind === 'Service' && ['NodePort', 'LoadBalancer'].includes(res.spec?.type) ? { message: `Service type ${res.spec.type}`, field: 'spec.type' } : null),
  },
];

export const RULE_INDEX = Object.freeze(Object.fromEntries(RULES.map((r) => [r.id, r])));

/** Evaluates all rules against one parsed resource. */
export function evaluateResource(res, docIndex = 0, { disabled = [] } = {}) {
  const findings = [];
  if (!res || typeof res !== 'object' || Array.isArray(res)) return findings;
  const off = new Set(disabled);
  const kind = String(res.kind ?? 'Unknown');
  const name = String(res.metadata?.name ?? '(unnamed)');
  const pod = podSpecOf(res);
  const push = (rule, hit, extra = {}) => {
    if (!hit) return;
    findings.push({ ruleId: rule.id, severity: rule.severity, title: rule.title, message: hit.message, field: hit.field, kind, name, docIndex, ...extra });
  };
  for (const rule of RULES) {
    if (off.has(rule.id)) continue;
    if (rule.resource) push(rule, rule.check({ res }));
    if (rule.pod && pod) push(rule, rule.check({ res, pod }));
    if (rule.containers && pod) {
      for (const ct of containersOf(pod)) push(rule, rule.check({ res, pod, c: { ...ct.c, name: ct.name }, init: ct.init }), { container: ct.name });
    }
  }
  return findings;
}

/** Score 0-100 and letter grade from findings. */
export function score(findings) {
  const penalty = findings.reduce((s, f) => s + (SEVERITY_WEIGHT[f.severity] ?? 0), 0);
  const value = Math.max(0, 100 - penalty);
  const grade = value >= 90 ? 'A' : value >= 75 ? 'B' : value >= 60 ? 'C' : value >= 40 ? 'D' : 'F';
  return { value, grade };
}
