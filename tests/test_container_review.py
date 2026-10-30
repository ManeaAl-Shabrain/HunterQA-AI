"""Owned saved JSON fixtures, never daemon/cluster requests or escape payloads."""
import copy
import hashlib
import json
import traceback
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.container_review import MAX_BYTES, PROFILES, WORKLOADS, review_evidence, review_file


def evidence(key="container-escape", value=None):
    return {"schema_version": 1, "records": [{"id": "owned-one", "skill": "offensive-" + key,
        "observations": dict.fromkeys(PROFILES[key], value)}]}


def native(tmp_path, monkeypatch, data, mode="kubernetes"):
    path = tmp_path / "source.json"
    path.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return path, review_file(path, authorized=True, mode=mode)


def pod(spec=None):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "PRIVATE", "namespace": "PRIVATE"},
        "spec": spec if spec is not None else {"containers": [{"name": "PRIVATE", "image": "PRIVATE", "env": [{"name":"PRIVATE","value":"PRIVATE"}]}]}}


def role(rule):
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "rules": [rule]}


def keys(report):
    return {f["rule_id"] for f in report["findings"]}


@pytest.mark.parametrize("key,field", [(k, f) for k, fs in PROFILES.items() for f in fs])
def test_both_contracts_positive_negative_and_unknown(key, field):
    data = evidence(key, True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field] = False
    report = review_evidence(data)
    assert [f["rule_id"] for f in report["findings"]] == ["container-review." + key + "." + field.replace("_", "-")]
    unknown = review_evidence(evidence(key))
    assert unknown["status"] == "insufficient-evidence" and not unknown["findings"]
    assert unknown["network_requests"] == unknown["external_tools_executed"] == unknown["containers_started"] == unknown["referenced_files_opened"] == 0
    assert not any(unknown[k] for k in ("runtime_enforcement_verified", "isolation_verified", "effective_permissions_computed", "all_skills_automated"))
    assert unknown["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change", [
    lambda d: d.update(schema_version=True), lambda d: d.update(schema_version=2), lambda d: d.update(extra="PRIVATE"),
    lambda d: d.update(records=[]), lambda d: d["records"][0].update(id="PRIVATE BAD"), lambda d: d["records"][0].update(skill=[]),
    lambda d: d["records"][0].update(skill="offensive-unknown"), lambda d: d["records"][0].update(extra="PRIVATE"),
    lambda d: d["records"][0].update(observations={}), lambda d: d["records"][0]["observations"].update(host_mounts_reviewed=1),
    lambda d: d["records"][0]["observations"].update(host_mounts_reviewed="PRIVATE"),
    lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
])
def test_strict_evidence_schema(change):
    data = evidence()
    change(data)
    with pytest.raises(ValueError) as exc:
        review_evidence(data)
    assert "PRIVATE" not in str(exc.value)


def test_template_catalog_record_bounds_and_coverage(capsys):
    data = {"schema_version": 1, "records": [{"id": k + "-" + str(i), "skill": "offensive-" + k,
        "observations": dict.fromkeys(fs, None)} for k, fs in PROFILES.items() for i in range(10)]}
    before = copy.deepcopy(data)
    assert len(review_evidence(data)["records"]) == 20 and before == data
    data["records"].append({**data["records"][0], "id": "extra"})
    with pytest.raises(ValueError):
        review_evidence(data)
    data["records"] = [{**data["records"][0], "id": "row-" + str(i)} for i in range(11)]
    with pytest.raises(ValueError):
        review_evidence(data)
    main(["container-review-catalog"])
    cat = json.loads(capsys.readouterr().out)
    assert len(cat["skills"]) == 2 and all(not r["active_exploitation_available"] for r in cat["skills"])
    root = Path(__file__).resolve().parents[1]
    report = review_evidence(json.loads((root / "templates/HunterQA-container-review-template.json").read_text()))
    assert len(report["records"]) == 2 and report["status"] == "insufficient-evidence"
    from hunterqa.coverage_audit import coverage_audit, render_checklist
    assert not coverage_audit()["all_seven_areas_complete"]
    assert next(p for p in coverage_audit()["category_packs"] if p["name"] == "Containers & Kubernetes")["skills"] == cat["skills"]
    assert (root / "docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()


@pytest.mark.parametrize("field,bad,quiet,key", [("Privileged", True, False, "privileged"), ("ReadonlyRootfs", False, True, "writable-rootfs"),
    ("NetworkMode", "host", "bridge", "host-networkmode"), ("PidMode", "host", "", "host-pidmode"),
    ("IpcMode", "host", "private", "host-ipcmode"), ("UsernsMode", "host", "", "host-usernsmode"),
    ("CapAdd", ["CAP_SYS_ADMIN"], [], "capabilities"), ("SecurityOpt", ["seccomp=unconfined"], [], "unconfined"),
    ("Memory", 0, 1024, "zero-memory-limit")])
def test_docker_selected_cues_and_negative_controls(tmp_path, monkeypatch, field, bad, quiet, key):
    _, report = native(tmp_path, monkeypatch, {"HostConfig": {field: bad}}, "docker-inspect")
    assert keys(report) == {"container-review.docker." + key}
    _, baseline = native(tmp_path, monkeypatch, {"HostConfig": {field: quiet}}, "docker-inspect")
    assert not baseline["findings"]


@pytest.mark.parametrize("user,root", [("0", True), ("root:PRIVATE", True), ("0:PRIVATE", True), ("1000", False), ("PRIVATE", False), ("", False)])
def test_docker_user_declarations_do_not_resolve_image_or_host_root(tmp_path, monkeypatch, user, root):
    _, report = native(tmp_path, monkeypatch, {"Config": {"User": user, "Env": ["PRIVATE"]}}, "docker-inspect")
    assert ("container-review.docker.root-user" in keys(report)) == root
    assert not report["source_review"]["image_users_resolved"] and "PRIVATE" not in json.dumps(report)


def test_docker_mounts_are_not_followed_and_unselected_fields_are_unknown(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, [{"Config": {"Env": ["PRIVATE"]}, "HostConfig": {"Binds": ["PRIVATE:PRIVATE"]},
        "Mounts": [{"Type":"bind","Source":"/var/run/docker.sock","Destination":"PRIVATE"}]}], "docker-inspect")
    assert keys(report) == {"container-review.docker.bind-mount", "container-review.docker.runtime-socket"}
    assert "PRIVATE" not in json.dumps(report) and not report["source_review"]["bind_strings_resolved"]
    _, missing = native(tmp_path, monkeypatch, {"Config": {}, "HostConfig": {"Unreviewed":"PRIVATE"}}, "docker-inspect")
    assert missing["status"] == "insufficient-evidence" and not missing["findings"]


@pytest.mark.parametrize("group", ("containers", "initContainers", "ephemeralContainers"))
@pytest.mark.parametrize("field,bad,quiet,key", [("privileged", True, False, "privileged"), ("allowPrivilegeEscalation", True, False, "allowprivilegeescalation"),
    ("readOnlyRootFilesystem", False, True, "readonlyrootfilesystem"), ("runAsUser", 0, 1000, "root-user"),
    ("runAsNonRoot", False, True, "nonroot-not-required")])
def test_all_container_groups_selected_positive_negative_controls(tmp_path, monkeypatch, group, field, bad, quiet, key):
    data = pod({group: [{"securityContext": {field: bad}}]})
    _, report = native(tmp_path, monkeypatch, data)
    assert keys(report) == {"container-review.k8s." + key}
    data["spec"][group][0]["securityContext"][field] = quiet
    _, baseline = native(tmp_path, monkeypatch, data)
    assert not baseline["findings"]


@pytest.mark.parametrize("profile", ("seccompProfile", "appArmorProfile"))
def test_profile_inheritance_and_container_override(tmp_path, monkeypatch, profile):
    data = pod({"securityContext": {profile: {"type":"Unconfined"}, "runAsUser":0}, "containers":[{"name":"PRIVATE"}]})
    _, inherited = native(tmp_path, monkeypatch, data)
    assert keys(inherited) == {"container-review.k8s." + profile.lower(), "container-review.k8s.root-user"}
    data["spec"]["containers"][0]["securityContext"] = {profile: {"type":"RuntimeDefault"}, "runAsUser":1000}
    _, overridden = native(tmp_path, monkeypatch, data)
    assert not overridden["findings"] and not overridden["runtime_enforcement_verified"]


@pytest.mark.parametrize("field", ("hostNetwork", "hostPID", "hostIPC", "automountServiceAccountToken"))
def test_pod_flags_missing_remain_unknown(tmp_path, monkeypatch, field):
    _, report = native(tmp_path, monkeypatch, pod({field: True}))
    assert keys(report) == {"container-review.k8s." + field.lower()}
    _, quiet = native(tmp_path, monkeypatch, pod({field: False}))
    assert not quiet["findings"]
    _, missing = native(tmp_path, monkeypatch, pod())
    assert missing["status"] == "insufficient-evidence" and not missing["findings"]


def test_capability_only_evidence_and_hostpath_socket_declarations(tmp_path, monkeypatch):
    data = pod({"containers":[{"securityContext":{"capabilities":{"add":["ALL"]}}}],
        "volumes":[{"name":"PRIVATE", "hostPath":{"path":"/run/containerd/containerd.sock"}}]})
    _, report = native(tmp_path, monkeypatch, data)
    assert keys(report) == {"container-review.k8s.capabilities", "container-review.k8s.hostpath", "container-review.k8s.runtime-socket"}
    assert report["records"][1]["status"] == "selected-declaration-only" and "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("kind", WORKLOADS)
def test_selected_controller_template_paths(tmp_path, monkeypatch, kind):
    version, path = WORKLOADS[kind]
    data = {"kind": kind, "apiVersion": version}
    current = data
    for field in path:
        current[field] = {}
        current = current[field]
    current.update({"hostPID": True})
    _, report = native(tmp_path, monkeypatch, data)
    assert keys(report) == {"container-review.k8s.hostpid"}


def test_windows_unknown_resources_and_empty_lists_are_not_passes(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, {"kind":"List","apiVersion":"v1","items":[pod({"os":{"name":"windows"},"hostPID":True}), {"kind":"Secret","apiVersion":"v1","data":{"PRIVATE":"PRIVATE"}}]})
    assert report["status"] == "insufficient-evidence" and not report["findings"]
    assert report["source_review"]["windows_workloads_not_reviewed"] == 1
    assert report["source_review"]["unsupported_objects_not_reviewed"] == 1
    assert "PRIVATE" not in json.dumps(report)
    for mode in ("docker-inspect", "kubernetes"):
        _, empty = native(tmp_path, monkeypatch, [], mode)
        assert empty["status"] == "insufficient-evidence"


@pytest.mark.parametrize("rule,key", [({"verbs":["*"],"resources":["pods"]}, "wildcard-rule"),
    ({"verbs":["get"],"resources":["*"],"resourceNames":["PRIVATE"]}, "wildcard-rule"),
    ({"verbs":["get"],"apiGroups":["*"]}, "wildcard-rule"), ({"verbs":["get"],"nonResourceURLs":["*"]}, "wildcard-rule"),
    ({"verbs":["bind"],"resources":["roles"]}, "sensitive-verb"), ({"verbs":["get"],"resources":["secrets"]}, "secret-read"),
    ({"verbs":["create"],"resources":["pods/exec"]}, "pod-exec")])
def test_rbac_selected_cues_do_not_compute_effective_access(tmp_path, monkeypatch, rule, key):
    data = role(rule)
    data["aggregationRule"] = {"clusterRoleSelectors":[{"matchLabels":{"PRIVATE":"PRIVATE"}}]}
    _, report = native(tmp_path, monkeypatch, data)
    assert keys(report) == {"container-review.rbac." + key}
    assert not report["effective_permissions_computed"] and not report["records"][0]["aggregation_resolved"]
    assert "PRIVATE" not in json.dumps(report)
    _, quiet = native(tmp_path, monkeypatch, role({"verbs":["get"],"resources":["pods"]}))
    assert not quiet["findings"]


def test_binding_role_names_and_subjects_do_not_establish_grants(tmp_path, monkeypatch):
    data = {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
        "roleRef":{"kind":"ClusterRole","name":"cluster-admin"}, "subjects":[{"kind":"Group","name":"system:authenticated"}]}
    _, report = native(tmp_path, monkeypatch, data)
    assert keys(report) == {"container-review.rbac.admin-role-name", "container-review.rbac.broad-subject"}
    assert not report["records"][0]["role_reference_resolved"]
    data["roleRef"]["name"] = "PRIVATE"
    data["subjects"] = [{"kind":"ServiceAccount","name":"PRIVATE"}]
    _, quiet = native(tmp_path, monkeypatch, data)
    assert not quiet["findings"] and "PRIVATE" not in json.dumps(quiet)


@pytest.mark.parametrize("mode,data", [("docker-inspect", {"HostConfig":{"Privileged":"PRIVATE"}}),
    ("docker-inspect", {"HostConfig":{"Memory":True}}), ("docker-inspect", {"Config":{"User":0}}),
    ("docker-inspect", {"Mounts":[{"Type":"bind","Source":[]}]}),
    ("kubernetes", pod({"hostPID":1})), ("kubernetes", pod({"securityContext":{"runAsUser":True}})),
    ("kubernetes", pod({"containers":[{"securityContext":{"seccompProfile":{"type":"PRIVATE"}}}]})),
    ("kubernetes", role({"verbs":"PRIVATE"})), ("kubernetes", {"kind":"RoleBinding","apiVersion":"rbac.authorization.k8s.io/v1","roleRef":[]})])
def test_malformed_selected_fields_fail_without_echo(mode, data, tmp_path, monkeypatch):
    with pytest.raises(ValueError) as exc:
        native(tmp_path, monkeypatch, data, mode)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


def test_native_collection_depth_and_node_limits(tmp_path, monkeypatch):
    for data, mode in (([{"HostConfig":{}}] * 101, "docker-inspect"), ([pod()] * 101, "kubernetes"),
        (pod({"containers":[{}] * 201}), "kubernetes"), (role({"verbs":["get"] * 101}), "kubernetes"),
        ({"kind":"ClusterRole","apiVersion":"rbac.authorization.k8s.io/v1","rules":[{}] * 201}, "kubernetes")):
        with pytest.raises(ValueError):
            native(tmp_path, monkeypatch, data, mode)
    data = pod()
    current = data
    for _ in range(42):
        current["nested"] = {}
        current = current["nested"]
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, data)
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, {"kind":"Secret","apiVersion":"v1","x":[0] * 20001})


def test_findings_truncation_and_record_bounds_are_explicit(tmp_path, monkeypatch):
    data = [{"HostConfig":{"Privileged":True,"ReadonlyRootfs":False,"NetworkMode":"host","PidMode":"host","IpcMode":"host","UsernsMode":"host"}} for _ in range(100)]
    _, report = native(tmp_path, monkeypatch, data, "docker-inspect")
    assert len(report["findings"]) == 500 and report["truncated"] and report["candidates_not_retained"] == 100
    data = [role({"verbs":[]}) for _ in range(10)]
    for obj in data:
        obj["rules"] *= 200
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, data)


INPUTS = [("normalized", evidence(value=False)), ("docker-inspect", {"HostConfig":{"Privileged":True}}), ("kubernetes", pod({"hostPID":True}))]


@pytest.mark.parametrize("mode,data", INPUTS)
def test_cli_authorization_receipts_private_nonoverwrite_and_scope(tmp_path, monkeypatch, mode, data):
    from hunterqa.sarif_export import export_sarif
    source, _ = native(tmp_path, monkeypatch, data, mode)
    output = tmp_path / "report.json"
    args = ["container-review" if mode == "normalized" else "container-config-review", "--input", str(source), "--out", str(output)]
    if mode != "normalized":
        args += ["--mode", mode]
    with pytest.raises(PermissionError):
        main(args)
    assert not output.exists()
    main([*args, "--authorized"])
    assert json.loads(output.read_text())["input_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert export_sarif(output)["runs"][0]["results"]
    before = output.read_bytes()
    with pytest.raises(FileExistsError):
        main([*args, "--authorized"])
    assert output.read_bytes() == before
    if __import__("os").name != "nt":
        assert output.stat().st_mode & 0o077 == 0
    root = tmp_path / "approved"
    root.mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    with pytest.raises(ValueError, match="outside"):
        review_file(source, authorized=True, mode=mode)
    inside = root / "source"
    inside.write_bytes(source.read_bytes())
    scoped = [str(inside) if a == str(source) else a for a in args]
    with pytest.raises(ValueError, match="outside"):
        main([*scoped, "--authorized"])
    inside.write_bytes(b"x" * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        review_file(inside, authorized=True, mode=mode)


@pytest.mark.parametrize("raw", [b'{"PRIVATE":NaN}', b'{"PRIVATE":1,"PRIVATE":2}', b'\xffPRIVATE', b'{"PRIVATE":', b'{"PRIVATE":1e999}'])
def test_json_errors_are_sanitized(tmp_path, monkeypatch, raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path, monkeypatch, raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


def test_no_daemon_cluster_socket_or_external_tool_connection(tmp_path, monkeypatch):
    import socket
    import subprocess

    def deny(*args, **kwargs):
        pytest.fail("Unexpected external action")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(subprocess, "Popen", deny)
    native(tmp_path, monkeypatch, {"Mounts":[{"Type":"bind","Source":"/var/run/docker.sock"}]}, "docker-inspect")
    native(tmp_path, monkeypatch, pod({"volumes":[{"hostPath":{"path":"/var/run/docker.sock"}}]}))
    with pytest.raises(ValueError):
        review_file(tmp_path / "never-opened", authorized=True, mode="unknown")


@pytest.mark.parametrize("mode,data", INPUTS)
def test_missing_roots_and_symlink_inputs_rejected(tmp_path, monkeypatch, mode, data):
    source, _ = native(tmp_path, monkeypatch, data, mode)
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS")
    with pytest.raises(ValueError):
        review_file(source, authorized=True, mode=mode)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    link = tmp_path / "link"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        review_file(link, authorized=True, mode=mode)


def test_empty_rbac_rules_do_not_imply_reviewed_permissions(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, role({}))
    assert report["status"] == "insufficient-evidence" and not report["findings"]


def test_receipts_distinguish_source_free_sarif_cases(tmp_path, monkeypatch):
    from hunterqa.sarif_export import export_sarif
    fingerprints = []
    for i in range(2):
        data = pod({"hostPID":True})
        data["metadata"]["name"] = "PRIVATE-" + str(i)
        _, report = native(tmp_path, monkeypatch, data)
        output = tmp_path / (str(i) + ".json")
        output.write_text(json.dumps(report))
        result = export_sarif(output)["runs"][0]["results"][0]
        fingerprints.append(result["partialFingerprints"])
        assert "PRIVATE" not in json.dumps(result)
    assert fingerprints[0] != fingerprints[1]
