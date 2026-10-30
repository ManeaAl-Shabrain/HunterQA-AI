"""Offline selected Docker inspect, Kubernetes workload and RBAC declarations."""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PROFILES = {
    "container-escape": ("runtime_patch_reviewed", "host_mounts_reviewed", "privilege_policy_reviewed", "namespace_isolation_reviewed", "capability_policy_reviewed"),
    "k8s-attacks": ("rbac_reviewed", "workload_identity_reviewed", "admission_policy_reviewed", "network_policy_reviewed", "control_plane_protection_reviewed"),
}
SOCKETS = {"/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/var/run/crio/crio.sock"}
CAPS = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE"}
WORKLOADS = {"Pod": ("v1", ("spec",)),
    **{k: ("apps/v1", ("spec", "template", "spec")) for k in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet")},
    "ReplicationController": ("v1", ("spec", "template", "spec")), "Job": ("batch/v1", ("spec", "template", "spec")),
    "CronJob": ("batch/v1", ("spec", "jobTemplate", "spec", "template", "spec"))}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/container",
    "https://docs.docker.com/reference/cli/docker/inspect/",
    "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
    "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-container-assurance-review", "fields": list(fields),
        "native_json_modes": ["docker-inspect"] if key == "container-escape" else ["kubernetes"],
        "active_exploitation_available": False,
        "required_evidence": "Private owner observations or selected saved container/workload/RBAC JSON; actual isolation, permissions and runtime state remain unverified"}
        for key, fields in PROFILES.items()]


def _failure():
    raise ValueError("Unsupported container evidence shape, selected field or bounds; contents withheld") from None


def _decode(raw):
    def pairs(entries):
        out = {}
        for key, value in entries:
            if key in out:
                _failure()
            out[key] = value
        return out

    def constant(_):
        _failure()

    try:
        data = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid container evidence JSON; contents withheld") from None
    stack, count = [(data, 0)], 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > 20000 or depth > 40 or (isinstance(value, float) and not math.isfinite(value)):
            _failure()
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return data


def _mapping(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        _failure()
    return value


def _list(value, maximum=100):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > maximum:
        _failure()
    return value


def _strings(value):
    result = _list(value)
    if not all(isinstance(v, str) and 1 <= len(v) <= 256 for v in result):
        _failure()
    return result


def _boolean(value):
    if value is not None and type(value) is not bool:
        _failure()
    return value


def _uid(value):
    if value is not None and (type(value) is not int or not 0 <= value <= 0xFFFFFFFF):
        _failure()
    return value


def _report():
    return {"engine": "container-evidence-review", "schema_version": 1, "category": "Containers & Kubernetes",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "records": [], "findings": [],
        "network_requests": 0, "external_tools_executed": 0, "containers_started": 0, "referenced_files_opened": 0,
        "runtime_enforcement_verified": False, "isolation_verified": False, "effective_permissions_computed": False,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "truncated": False, "candidates_not_retained": 0,
        "references": REFERENCES, "limitations": ["Selected offline declarations only; no Docker daemon, socket, Kubernetes API, node or cluster connection",
            "No container escape, workload execution, resource mutation, privilege escalation, token/secret access or exploit payload",
            "No image/user resolution, admission mutation, service-account inheritance, namespace mapping or effective RBAC/aggregation calculation",
            "No YAML, Helm/Compose evaluation, full schema validation, image/CVE scan or Pod Security Standards compliance verdict",
            "Missing declarations remain unknown; risky-looking settings may be intentional and do not demonstrate exploitability",
            "Names, IDs, paths, images, labels, environments, subjects and secret values are withheld; hashes do not prove provenance or owner consent"]}


def _record(report, case, skill, context, **fields):
    if len(report["records"]) >= 2000:
        _failure()
    row = {"case": case, "skill": skill, "context": context, "status": "selected-declaration-only", **fields}
    report["records"].append(row)
    return row


def _add(report, case, skill, key, title, fix):
    if len(report["findings"]) >= MAX_FINDINGS:
        report["truncated"] = True
        report["candidates_not_retained"] += 1
        return
    report["findings"].append({"rule_id": "container-review." + key.replace("_", "-"), "skill": skill,
        "test_case": case, "title": title, "severity": "INFO", "cwe": "CWE-693",
        "message": title + ". " + fix, "remediation": fix, "code": "", "file_path": "external-evidence",
        "line_start": 1, "line_end": 1, "engine": "container-evidence-review", "verification_status": "unverified"})


def _finish(report):
    rows = report["records"]
    report["status"] = "insufficient-evidence" if not rows or all(r["status"] == "insufficient-evidence" for r in rows) else "partial-offline-review"
    return report


def review_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["records"], list) or not 1 <= len(data["records"]) <= 20:
        _failure()
    report, ids, counts = _report(), set(), {}
    for row in data["records"]:
        if not isinstance(row, dict) or set(row) != {"id", "skill", "observations"}:
            _failure()
        if not isinstance(row["id"], str) or not ID.fullmatch(row["id"]) or row["id"] in ids:
            _failure()
        ids.add(row["id"])
        skill, obs = row["skill"], row["observations"]
        if not isinstance(skill, str) or not skill.startswith("offensive-") or skill[10:] not in PROFILES:
            _failure()
        key = skill[10:]
        counts[key] = counts.get(key, 0) + 1
        if counts[key] > 10 or not isinstance(obs, dict) or set(obs) != set(PROFILES[key]) or not all(v is None or type(v) is bool for v in obs.values()):
            _failure()
        for field, value in obs.items():
            if value is False:
                _add(report, row["id"], skill, key + "." + field, "Owner evidence declares incomplete container assurance: " + field.replace("_", " "),
                    "Review applicable runtime, workload and independent evidence; this declaration does not demonstrate a vulnerability.")
        unknown = [f for f, v in obs.items() if v is None]
        _record(report, row["id"], skill, "owner-evidence", unknown_fields=unknown,
            status="insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence")
    return _finish(report)


def _docker(data, receipt):
    objects = data if isinstance(data, list) else [data]
    if len(objects) > 100:
        _failure()
    report, skill = _report(), "offensive-container-escape"
    for i, obj in enumerate(objects, 1):
        if not isinstance(obj, dict) or not any(k in obj for k in ("Config", "HostConfig", "Mounts")):
            _failure()
        config, host = _mapping(obj.get("Config")), _mapping(obj.get("HostConfig"))
        case = "ctr-" + receipt[:12] + "-docker-" + str(i)
        fields = ("Privileged", "ReadonlyRootfs")
        flags = {k: _boolean(host.get(k)) for k in fields}
        user = config.get("User")
        if user is not None and not isinstance(user, str):
            _failure()
        row = _record(report, case, skill, "docker-inspect", unknown_fields=[k for k, v in flags.items() if v is None],
            user_declaration="unspecified" if not user else ("root-style" if user.split(":", 1)[0] in ("0", "root") else "other-nonempty-not-resolved"))
        if flags["Privileged"] is True:
            _add(report, case, skill, "docker.privileged", "Inspect declares privileged mode", "Review intended access and actual daemon/user-namespace enforcement; host compromise is not demonstrated.")
        if flags["ReadonlyRootfs"] is False:
            _add(report, case, skill, "docker.writable-rootfs", "Inspect explicitly declares a writable root filesystem", "Review application write requirements and compensating controls; this setting can be intentional.")
        if row["user_declaration"] == "root-style":
            _add(report, case, skill, "docker.root-user", "Inspect has a root-style user declaration", "Review actual image account resolution and namespace mappings; no host-level privilege is inferred.")
        for key in ("NetworkMode", "PidMode", "IpcMode", "UsernsMode"):
            value = host.get(key)
            if value is not None and not isinstance(value, str):
                _failure()
            if value == "host":
                _add(report, case, skill, "docker.host-" + key.lower(), "Inspect declares a selected host namespace mode", "Review intended namespace sharing and actual runtime isolation independently.")
        caps = _strings(host.get("CapAdd"))
        if any(c.removeprefix("CAP_") in CAPS for c in caps):
            _add(report, case, skill, "docker.capabilities", "Inspect declares selected broad added capabilities", "Review drops, namespace context and effective capabilities; additions alone do not prove an escape path.")
        options = _strings(host.get("SecurityOpt"))
        if any(v in ("seccomp=unconfined", "apparmor=unconfined") for v in options):
            _add(report, case, skill, "docker.unconfined", "Inspect declares an unconfined seccomp/AppArmor option", "Review daemon/platform defaults and intended exceptions; actual enforcement is not tested.")
        memory = host.get("Memory")
        if memory is not None and (type(memory) is not int or memory < 0):
            _failure()
        if memory == 0:
            _add(report, case, skill, "docker.zero-memory-limit", "Inspect declares zero for the container memory limit", "Review parent cgroup/host policy and intended workload limits; this does not establish unlimited host resources.")
        mounts = _list(obj.get("Mounts"))
        for j, mount in enumerate(mounts, 1):
            mount = _mapping(mount)
            if mount.get("Type") == "bind":
                if not isinstance(mount.get("Source"), str):
                    _failure()
                m = case + "-mount-" + str(j)
                _record(report, m, skill, "docker-bind", mount_index=j)
                _add(report, m, skill, "docker.bind-mount", "Inspect declares a host bind mount", "Review source/destination, write access and intended trust; no mounted path is read or followed.")
                if mount.get("Source") in SOCKETS:
                    _add(report, m, skill, "docker.runtime-socket", "Bind source matches a selected runtime-socket path", "Review the actual mount and socket permissions; no socket connection or daemon-control test occurs.")
        if not any(host.get(k) is not None for k in (*fields, "NetworkMode", "PidMode", "IpcMode", "UsernsMode", "CapAdd", "SecurityOpt", "Memory")) and not user and not mounts:
            row["status"] = "insufficient-evidence"
    report["source_review"] = {"objects_reviewed": len(objects), "bind_strings_resolved": False, "image_users_resolved": False,
        "rootless_or_user_namespace_effects_computed": False, "native_source_line_locations_available": False}
    return _finish(report)


def _profile(value):
    obj = _mapping(value)
    if obj and obj.get("type") not in ("Unconfined", "RuntimeDefault", "Localhost"):
        _failure()
    return obj.get("type")


def _pod(spec, report, case):
    skill = "offensive-k8s-attacks"
    os_name = _mapping(spec.get("os")).get("name")
    if os_name not in (None, "linux", "windows"):
        _failure()
    if os_name == "windows":
        return False
    security = _mapping(spec.get("securityContext"))
    flags = {k: _boolean(spec.get(k)) for k in ("hostNetwork", "hostPID", "hostIPC", "automountServiceAccountToken")}
    row = _record(report, case, skill, "kubernetes-pod-spec", os_applicability="linux-declared" if os_name == "linux" else "unspecified-not-verified",
        unknown_fields=[k for k, v in flags.items() if v is None])
    if all(v is None for v in flags.values()):
        row["status"] = "insufficient-evidence"
    for key, value in flags.items():
        if value is True:
            _add(report, case, skill, "k8s." + key.lower(), "Pod spec explicitly declares a selected host-sharing/token setting", "Review intended namespace/token use and admission/service-account effects; actual access is not established.")
    inherited = {"runAsUser": _uid(security.get("runAsUser")), "runAsNonRoot": _boolean(security.get("runAsNonRoot")),
        "seccompProfile": _profile(security.get("seccompProfile")), "appArmorProfile": _profile(security.get("appArmorProfile"))}
    total = 0
    for group in ("containers", "initContainers", "ephemeralContainers"):
        for i, container in enumerate(_list(spec.get(group), 200), 1):
            total += 1
            if total > 200:
                _failure()
            container = _mapping(container)
            context = _mapping(container.get("securityContext"))
            selected = {k: context.get(k) if context.get(k) is not None else v for k, v in inherited.items()}
            selected["runAsUser"] = _uid(selected["runAsUser"])
            selected["runAsNonRoot"] = _boolean(selected["runAsNonRoot"])
            for key in ("seccompProfile", "appArmorProfile"):
                if key in context and context[key] is not None:
                    selected[key] = _profile(context[key])
            local = {k: _boolean(context.get(k)) for k in ("privileged", "allowPrivilegeEscalation", "readOnlyRootFilesystem")}
            c = case + "-" + {"containers": "c", "initContainers": "i", "ephemeralContainers": "e"}[group] + str(i)
            record = _record(report, c, skill, "kubernetes-container", container_group=group, container_index=i,
                unknown_fields=[k for k, v in {**selected, **local}.items() if v is None],
                capabilities_add_declared=_mapping(context.get("capabilities")).get("add") is not None)
            if len(record["unknown_fields"]) == len(selected) + len(local) and not record["capabilities_add_declared"]:
                record["status"] = "insufficient-evidence"
            for key, bad in (("privileged", True), ("allowPrivilegeEscalation", True), ("readOnlyRootFilesystem", False)):
                if local[key] is bad:
                    _add(report, c, skill, "k8s." + key.lower(), "Container context explicitly declares a selected relaxed control", "Review intended workload behavior and actual admission/runtime enforcement; this is not a demonstrated escape.")
            if selected["runAsUser"] == 0:
                _add(report, c, skill, "k8s.root-user", "Selected user declaration resolves to numeric zero", "Review namespace mapping, runAsNonRoot conflicts and actual admitted state; host-level root is not inferred.")
            if selected["runAsNonRoot"] is False:
                _add(report, c, skill, "k8s.nonroot-not-required", "Selected context explicitly does not require non-root execution", "Review actual image user and workload policy; this does not prove the process runs as root.")
            for key in ("seccompProfile", "appArmorProfile"):
                if selected[key] == "Unconfined":
                    _add(report, c, skill, "k8s." + key.lower(), "Selected context declares an unconfined protection profile", "Review OS/version applicability, inherited settings and actual runtime enforcement.")
            if any(v.removeprefix("CAP_") in CAPS for v in _strings(_mapping(context.get("capabilities")).get("add"))):
                _add(report, c, skill, "k8s.capabilities", "Container context declares selected broad added capabilities", "Review drops, namespaces and effective runtime capability sets; no effective privilege calculation occurs.")
    for i, volume in enumerate(_list(spec.get("volumes")), 1):
        volume = _mapping(volume)
        if volume.get("hostPath") is not None:
            host = _mapping(volume["hostPath"])
            if not isinstance(host.get("path"), str):
                _failure()
            v = case + "-volume-" + str(i)
            _record(report, v, skill, "kubernetes-hostpath", volume_index=i)
            _add(report, v, skill, "k8s.hostpath", "Pod spec declares a hostPath volume", "Review intended mount use and access; a volume declaration does not prove a container mounts or can access it.")
            if host["path"] in SOCKETS:
                _add(report, v, skill, "k8s.runtime-socket", "HostPath matches a selected runtime-socket path", "Verify actual volume mounts and permissions independently; no socket is opened.")
    return True


def _rbac(obj, report, case):
    skill, kind = "offensive-k8s-attacks", obj["kind"]
    if kind in ("Role", "ClusterRole"):
        rules = _list(obj.get("rules"), 200)
        role_row = _record(report, case, skill, "kubernetes-role", status="insufficient-evidence",
            aggregation_declared=obj.get("aggregationRule") is not None, aggregation_resolved=False)
        for i, rule in enumerate(rules, 1):
            rule = _mapping(rule)
            verbs, resources, groups = _strings(rule.get("verbs")), _strings(rule.get("resources")), _strings(rule.get("apiGroups"))
            restrictions = _strings(rule.get("resourceNames"))
            c = case + "-rule-" + str(i)
            known = any(rule.get(k) is not None for k in ("verbs", "resources", "apiGroups", "nonResourceURLs", "resourceNames"))
            _record(report, c, skill, "kubernetes-rbac-rule", rule_index=i, resource_name_restriction_declared=bool(restrictions),
                status="selected-declaration-only" if known else "insufficient-evidence")
            if known:
                role_row["status"] = "selected-declaration-only"
            cues = []
            if "*" in verbs or "*" in resources or "*" in groups or "*" in _strings(rule.get("nonResourceURLs")):
                cues.append(("wildcard-rule", "Role rule declares selected wildcard scope"))
            if any(v in verbs for v in ("bind", "escalate", "impersonate")):
                cues.append(("sensitive-verb", "Role rule declares selected sensitive authorization verbs"))
            if "secrets" in resources and any(v in verbs for v in ("get", "list", "watch", "*")):
                cues.append(("secret-read", "Role rule declares secret-read operations"))
            if "pods/exec" in resources and any(v in verbs for v in ("create", "*")):
                cues.append(("pod-exec", "Role rule declares pod-exec creation scope"))
            for key, title in cues:
                _add(report, c, skill, "rbac." + key, title, "Review API groups, resource-name restrictions, namespace/bindings and intended duties; effective access and exploitability are not computed.")
    else:
        role = _mapping(obj.get("roleRef"))
        if role.get("kind") not in ("Role", "ClusterRole") or not isinstance(role.get("name"), str):
            _failure()
        subjects = _list(obj.get("subjects"), 200)
        _record(report, case, skill, "kubernetes-binding", subject_count=len(subjects), role_reference_resolved=False)
        if role["kind"] == "ClusterRole" and role["name"] == "cluster-admin":
            _add(report, case, skill, "rbac.admin-role-name", "Binding references the conventional cluster-administration role name", "Verify actual role contents and binding scope independently; the name alone does not establish effective administration.")
        broad = False
        for subject in subjects:
            subject = _mapping(subject)
            name = subject.get("name")
            if subject.get("kind") not in ("User", "Group", "ServiceAccount") or not isinstance(name, str):
                _failure()
            broad = broad or (subject["kind"] == "Group" and (name in ("system:authenticated", "system:unauthenticated", "system:serviceaccounts") or name.startswith("system:serviceaccounts:")))
        if broad:
            _add(report, case, skill, "rbac.broad-subject", "Binding declares a selected broad built-in subject group", "Review intended membership, referenced role and namespace scope; no subject identity or effective permission is verified.")


def _kubernetes(data, receipt):
    if isinstance(data, dict) and data.get("kind") == "List":
        if data.get("apiVersion") != "v1":
            _failure()
        objects = _list(data.get("items"))
    else:
        objects = data if isinstance(data, list) else [data]
    if len(objects) > 100:
        _failure()
    report, skipped, windows = _report(), 0, 0
    for i, obj in enumerate(objects, 1):
        if not isinstance(obj, dict) or not isinstance(obj.get("kind"), str):
            _failure()
        kind = obj["kind"]
        case = "ctr-" + receipt[:12] + "-k8s-" + str(i)
        if kind in WORKLOADS and obj.get("apiVersion") == WORKLOADS[kind][0]:
            selected = obj
            for key in WORKLOADS[kind][1]:
                selected = _mapping(selected.get(key))
            if not _pod(selected, report, case):
                windows += 1
        elif kind in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding") and obj.get("apiVersion") == "rbac.authorization.k8s.io/v1":
            _rbac(obj, report, case)
        else:
            skipped += 1
    report["source_review"] = {"input_objects": len(objects), "unsupported_objects_not_reviewed": skipped, "windows_workloads_not_reviewed": windows,
        "admission_or_service_account_defaults_resolved": False, "complete_kubernetes_validation": False,
        "pod_security_standards_compliance_verified": False, "native_source_line_locations_available": False}
    return _finish(report)


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("Container evidence review requires explicit authorization")
    if mode not in ("normalized", "docker-inspect", "kubernetes"):
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    data, receipt = _decode(raw), hashlib.sha256(raw).hexdigest()
    report = review_evidence(data) if mode == "normalized" else (_docker if mode == "docker-inspect" else _kubernetes)(data, receipt)
    report.update(input_sha256=receipt, input_mode=mode)
    return report
