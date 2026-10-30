# Containers & Kubernetes review pack

**Post-v1.3.0 development capability.** Two offline contracts review owner evidence.
Selected native readers inspect existing Docker inspect and Kubernetes workload/
RBAC JSON. They do not connect to a daemon/cluster, start containers, mutate
resources, read mounted paths or attempt an escape.

Category vocabulary references [Claude-Red](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/container).
HunterQA's implementation is original. Upstream payloads, tool scripts and operational
instructions are not imported, installed or executed.

## Coverage and uncertainty

| Contract | Selected observations |
| --- | --- |
| `offensive-container-escape` | Runtime patch, host mount, privilege, namespace and capability policy review |
| `offensive-k8s-attacks` | RBAC, workload identity, admission, network policy and control-plane protection review |

INFO cues are unverified review aids, not CVSS or demonstrated vulnerabilities.
Declared privileges/mounts may be intentional. No effective isolation, authorization,
runtime CVE applicability or Pod Security Standards compliance is established.
All broad readiness areas remain partial; real-world effectiveness is unverified.

## 1. Private owner observations

After merging and pulling, activate the development environment and refresh with
`python -m pip install -e .`. This pack adds no dependency, Docker/Kubernetes SDK,
daemon requirement or external binary. Use already collected owner-approved files.

Copy [the JSON template](../templates/HunterQA-container-review-template.json) and
[private worksheet](../templates/17-container-kubernetes-review.md) outside the
checkout. Keep approvals, identifiers, configurations, tokens and reports private.

```bash
umask 077
mkdir -p "$HOME/hunterqa-cases/containers"
cp templates/HunterQA-container-review-template.json "$HOME/hunterqa-cases/containers/evidence.json"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases/containers"
# Edit only the private copy using applicable, independently reviewed evidence.
hunterqa container-review-catalog
hunterqa container-review \
  --input "$HOME/hunterqa-cases/containers/evidence.json" \
  --out "$HOME/hunterqa-cases/containers/review.json" \
  --authorized
```

Review JSON has exactly `schema_version: 1` and `records`. Each record has exactly
`id`, `skill`, `observations`; catalog/template list the exact required fields.
Neutral IDs are unique and match `[a-z][a-z0-9-]{0,47}`. Observations must be boolean
or null. False means a declared incomplete review; null means unknown. An untouched
template reports insufficient evidence, not a pass. Remove inapplicable records.
Maximum ten records per contract, 20 total.

## 2. Selected Docker inspect JSON

Supply a previously collected container inspect object or array, not an image,
Compose file, Dockerfile, socket, kubeconfig or live endpoint.

```bash
hunterqa container-config-review \
  --mode docker-inspect \
  --input "$HOME/hunterqa-cases/containers/inspect.json" \
  --out "$HOME/hunterqa-cases/containers/docker-review.json" \
  --authorized
```

The selected Linux-style review checks explicit privileged/read-only-root flags,
host network/PID/IPC/user namespace modes, selected added capabilities, unconfined
seccomp/AppArmor option literals, user text and a zero memory-limit declaration.
Absent/null fields remain unknown. An empty user string is unspecified; image
accounts/defaults are not resolved. A root-style user declaration does not prove
host root because namespace mappings and runtime policy are unverified. A zero
memory setting does not establish unlimited host resources; parent policies may apply.

Only `Mounts` entries with `Type: bind` are reviewed for host bind declarations
and exact selected runtime-socket source paths. `HostConfig.Binds` strings are not
resolved or interpreted. Paths are never read/followed and no socket is opened.
Named volumes, devices, image content, resource tuning beyond the selected memory
field, alternative option syntax and effective capability/drop calculation are not
assessed. Docker inspection validity/platform applicability is not fully checked.

## 3. Selected Kubernetes JSON

```bash
hunterqa container-config-review \
  --mode kubernetes \
  --input "$HOME/hunterqa-cases/containers/resources.json" \
  --out "$HOME/hunterqa-cases/containers/kubernetes-review.json" \
  --authorized
```

Input can be one complete object, a JSON array of complete objects, or a `v1` `List`
with complete objects in `items`. Nested/typed list kinds are not expanded. Maximum
100 objects. Unsupported kinds/API versions are counted as not reviewed. Secrets,
ConfigMaps, kubeconfig, network policies, CRDs, admission configuration and cluster
state are not interpreted by the native reader. No secret value is decoded/exported.

| Supported resource | API version / selected scope |
| --- | --- |
| Pod | `v1`, direct spec |
| Deployment, StatefulSet, DaemonSet, ReplicaSet | `apps/v1`, template spec |
| ReplicationController | `v1`, template spec |
| Job, CronJob | `batch/v1`, selected job/pod template spec |
| Role, ClusterRole, RoleBinding, ClusterRoleBinding | `rbac.authorization.k8s.io/v1`, selected rule/binding declarations |

### Workloads

Explicit Windows workloads are skipped and counted. For Linux/unspecified OS,
selected host network/PID/IPC and service-account-token flags are reviewed.
An unspecified OS is not verified as Linux. Missing token flags do not infer
automatic mounting; service-account defaults, projected tokens and admission
effects are not resolved.

Regular, init and ephemeral container contexts are checked. Only selected
`runAsUser`, `runAsNonRoot`, seccomp and AppArmor declarations inherit from the pod
context, with explicit container values taking precedence. Privileged,
allowPrivilegeEscalation and readOnlyRootFilesystem are container-local checks.
Explicit zero UID, non-root not required, relaxed flags, selected added capabilities
and unconfined profiles produce review cues. A UID/profile declaration may conflict
with admission requirements; it does not prove a running process or host privilege.

Added capability cues cover ALL, SYS_ADMIN, SYS_PTRACE, NET_ADMIN and SYS_MODULE,
including the selected `CAP_` prefix form. Drops and effective sets are not evaluated.
Only structured seccomp/AppArmor profile types are selected; legacy annotations,
localhost profile content and platform/version behavior are not verified.

HostPath volume declarations produce cues, with extra review for exact selected
socket paths. Declaring a volume does not prove a container mounts or can access it.
No volumeMount/permission graph, path normalization or symlink resolution occurs.
Selected exact socket paths are `/var/run/docker.sock`, `/run/docker.sock`,
`/run/containerd/containerd.sock`, `/var/run/crio/crio.sock`; aliases remain unassessed.

### RBAC

Selected rules are reviewed for wildcard verbs/resources/API groups/non-resource
URLs, bind/escalate/impersonate verbs, secret-read operations and pod-exec creation
scope. Resource-name restriction presence is retained without exporting names.
API-group applicability, restrictions, namespaces, bindings and actual subject
membership require independent review. Rules are never simulated as effective grants.

Role aggregation is noted without resolving selectors. Binding role references
are not resolved, including conventional administrative role names. Selected broad
built-in group declarations prompt review; no actual group membership is inferred.
No role is created/updated, token obtained, secret read or workload executed.

## Bounds, reports and validation

Files must be approved local regular JSON files of at most 1 MiB. Duplicate keys,
non-finite numbers, more than 20,000 JSON values or depth 40 are rejected with
contents withheld. Optional null mappings/lists/booleans are treated as absent/
unknown, not as secure defaults. Selected UID values are unsigned 32-bit integers.
Native limits include 100 objects, 200 total container entries per pod spec, 100
volumes/mounts/capability strings, 200 rules per role, 100 strings per selected rule
field, 200 binding subjects and 2000 retained records. These are selected readers,
not complete platform schema validators. At most 500 findings are retained, with
explicit truncation and dropped counts.

Authorization is an operator attestation, not independently verified owner consent.
Output parents must already exist inside approved roots. The existing writer creates
private/create-only files and never overwrites prior reports. On Windows use an
access-controlled private case directory; secure input permissions yourself.

Reports retain UTC time, exact input SHA-256, receipt-derived case/object/container/
rule indices, unknown fields, skipped counts and remediation. Names, namespaces,
images, labels, paths, subjects, environment contents and secrets are withheld.
Hashes do not prove provenance or anonymity. Native source-line coordinates are
not claimed; privately map case indices to the original export. SARIF uses an
external-evidence placeholder. Runtime/isolation/permission verification flags stay false.

```bash
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/containers/kubernetes-review.json" \
  --out "$HOME/hunterqa-cases/containers/kubernetes-review.sarif"
```

Tests use owned synthetic JSON, with positive/negative/unknown cases, override
precedence, all selected container groups, RBAC context, privacy, bounds and
non-overwrite. They do not demonstrate real-world escapes, live cluster detection
effectiveness, actual permissions or complete platform/standards coverage.

## References and next category

- [Docker inspect](https://docs.docker.com/reference/cli/docker/inspect/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

The next pack is [CI/CD & Pipelines](CICD_PIPELINES_REVIEW.md), delivered separately.
