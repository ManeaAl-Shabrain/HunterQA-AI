"""Owned synthetic CI/CD declarations; no workflows, tools or secret access."""
import copy
import hashlib
import json
import socket
import subprocess
import traceback
from pathlib import Path

import pytest

from hunterqa.cicd_review import MAX_BYTES, PROFILES, review_evidence, review_file
from hunterqa.cli import main


def evidence(key="cicd-pipeline", value=None):
    return {"schema_version": 1, "records": [{"id": "owned-one", "skill": "offensive-" + key,
        "observations": dict.fromkeys(PROFILES[key], value)}]}


def native(tmp_path, monkeypatch, data):
    path = tmp_path / "source.json"
    path.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return path, review_file(path, authorized=True, mode="github-actions-json")


def workflow(**job):
    return {"on": "workflow_dispatch", "permissions": {}, "jobs": {"PRIVATE": job or {"steps": [{"run": "echo PRIVATE"}]}}}


def keys(report):
    return {f["rule_id"].removeprefix("cicd-review.") for f in report["findings"]}


@pytest.mark.parametrize("key,field", [(k, f) for k, fs in PROFILES.items() for f in fs])
def test_contract_positive_negative_unknown(key, field):
    data = evidence(key, True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field] = False
    assert len(review_evidence(data)["findings"]) == 1
    report = review_evidence(evidence(key))
    assert report["status"] == "insufficient-evidence"
    assert report["network_requests"] == report["external_tools_executed"] == report["referenced_files_opened"] == 0
    assert not report["all_skills_automated"] and report["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change", [lambda d:d.update(schema_version=True), lambda d:d.update(records=[]),
    lambda d:d.update(extra="PRIVATE"), lambda d:d["records"][0].update(id="PRIVATE BAD"),
    lambda d:d["records"][0].update(skill=[]), lambda d:d["records"][0].update(observations={}),
    lambda d:d["records"][0]["observations"].update(dependencies_pinned=1),
    lambda d:d["records"].append(copy.deepcopy(d["records"][0]))])
def test_strict_contract(change):
    data = evidence()
    change(data)
    with pytest.raises(ValueError, match="withheld"):
        review_evidence(data)


@pytest.mark.parametrize("ref,expected", [("owner/action@v4", "action-not-sha"),
    ("owner/action@" + "a"*40, None), ("./local/action", None),
    ("docker://image:latest", "image-not-digest"), ("docker://image@sha256:"+"b"*64, None),
    ("${{ inputs.action }}", "unresolved-action")])
def test_reference_cues(tmp_path, monkeypatch, ref, expected):
    _, report = native(tmp_path, monkeypatch, workflow(steps=[{"uses":ref}]))
    assert keys(report) == ({expected} if expected else set())


@pytest.mark.parametrize("base,job,expected", [("write-all", {}, {"permissions-write-all"}),
    ("write-all", {"permissions":{}}, {"permissions-write-all"}),
    ({"contents":"write"}, {}, {"permissions-write"}), ("read-all", {}, set()),
    ({}, {"permissions":{"id-token":"write"}}, {"permissions-write"}), ({}, {}, set())])
def test_permission_inheritance(tmp_path, monkeypatch, base, job, expected):
    data = workflow(**job)
    data["permissions"] = base
    _, report = native(tmp_path, monkeypatch, data)
    assert keys(report) == expected
    if "permissions" in job:
        assert report["records"][0]["permissions_declaration"] == "explicit-map"
    assert not report["effective_permissions_verified"]


@pytest.mark.parametrize("event", ["pull_request_target", ["pull_request_target"], {"pull_request_target": {"types":["opened"]}}])
def test_privileged_event_and_secret_boundary(tmp_path, monkeypatch, event):
    data = workflow(uses="owner/repo/.github/workflows/build.yml@"+"a"*40, secrets="inherit")
    data["on"] = event
    _, report = native(tmp_path, monkeypatch, data)
    assert keys(report) == {"privileged-event", "secrets-inherit"}
    assert not report["secret_protection_verified"]


@pytest.mark.parametrize("run,expected", [("echo ${{ github.event.issue.title }}", True),
    ("echo ${{ github . event . pull_request.body }}", True), ("echo ${{ github.head_ref }}", True),
    ("echo ${{ github.sha }}", False), ("echo $SAFE_INPUT", False)])
def test_selected_untrusted_context(tmp_path, monkeypatch, run, expected):
    _, report = native(tmp_path, monkeypatch, workflow(steps=[{"run":run}]))
    assert ("untrusted-script-context" in keys(report)) == expected


@pytest.mark.parametrize("data", [{}, {"jobs":{}}, {"jobs":[]}, workflow(permissions=None),
    {**workflow(), "permissions":None}, workflow(permissions={"contents":"PRIVATE"}),
    workflow(steps=[{"run":1}]), workflow(steps=[{"uses":"x","run":"PRIVATE"}]),
    workflow(secrets="PRIVATE"), workflow(steps=[{}]), workflow(steps=[{"run":"x"}]*201),
    {**workflow(), "on":[1]}, workflow(uses="x", steps=[]), workflow(steps="PRIVATE")])
def test_bad_native_shapes(tmp_path, monkeypatch, data):
    with pytest.raises(ValueError) as exc:
        native(tmp_path, monkeypatch, data)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("raw", [b'{"jobs":{},"jobs":{}}', b'{"private":NaN}', b'{"private":1e9999}',
    b'PRIVATE', b'\xff', b'['*45+b'0'+b']'*45, b' '* (MAX_BYTES+1)])
def test_parser_bounds_and_sanitized_errors(tmp_path, monkeypatch, raw):
    with pytest.raises((ValueError, OSError)) as exc:
        native(tmp_path, monkeypatch, raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_no_network_execution_or_source_leaks(tmp_path, monkeypatch):
    def deny(*args, **kwargs):
        pytest.fail("Offline reader attempted network or process execution")
    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(subprocess, "Popen", deny)
    data = workflow(steps=[{"run":"echo ${{ github.event.issue.title }} PRIVATE", "env":{"PRIVATE":"PRIVATE"}},
        {"uses":"owner/PRIVATE@v1", "with":{"token":"PRIVATE"}}], secrets={"PRIVATE":"PRIVATE"})
    path, report = native(tmp_path, monkeypatch, data)
    assert "PRIVATE" not in json.dumps(report)
    assert report["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert all(f["severity"] == "INFO" and f["verification_status"] == "unverified" for f in report["findings"])


def test_cli_template_output_and_coverage(tmp_path, monkeypatch, capsys):
    template = Path("templates/HunterQA-cicd-review-template.json").read_text()
    source = tmp_path/"source.json"
    source.write_text(template)
    out = tmp_path/"report.json"
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    main(["cicd-review", "--input",str(source),"--out",str(out),"--authorized"])
    assert json.loads(out.read_text())["status"] == "insufficient-evidence"
    with pytest.raises(FileExistsError):
        main(["cicd-review", "--input",str(source),"--out",str(out),"--authorized"])
    main(["cicd-review-catalog"])
    assert "offensive-cicd-secrets" in capsys.readouterr().out
    from hunterqa.coverage_audit import coverage_audit, render_checklist
    assert Path("docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()
    assert not coverage_audit()["all_seven_areas_complete"]
    assert any(p["name"] == "CI/CD & Pipelines" for p in coverage_audit()["category_packs"])


def test_authorization_and_roots(tmp_path, monkeypatch):
    missing=tmp_path/"absent.json"
    with pytest.raises(PermissionError):
        review_file(missing)
    source=tmp_path/"source.json"
    source.write_text(json.dumps(workflow()))
    (tmp_path/"other").mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path/"other"))
    with pytest.raises(ValueError):
        review_file(source,authorized=True)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    link=tmp_path/"link.json"
    link.symlink_to(source)
    with pytest.raises(ValueError):
        review_file(link, authorized=True)
    with pytest.raises(ValueError):
        review_file(source, authorized=True, mode="yaml")

def test_unknown_defaults_and_finding_truncation(tmp_path, monkeypatch):
    data = workflow(steps=[{"uses":"owner/action@v1"}]*200)
    data.pop("permissions")
    data.pop("on")
    data["jobs"] = {str(i):data["jobs"]["PRIVATE"] for i in range(5)}
    _, report = native(tmp_path, monkeypatch, data)
    assert report["truncated"] and len(report["findings"]) == 500
    assert report["candidates_not_retained"] == 500
    assert all(r["permissions_declaration"] == "unknown-default" and not r["event_context_known"] for r in report["records"])
    data["jobs"]["extra"] = {"steps":[{"run":"echo owned"}]}
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, data)


def test_sarif_receipt_context_and_native_cli(tmp_path, monkeypatch):
    from hunterqa.sarif_export import export_sarif
    source, report = native(tmp_path, monkeypatch, workflow(steps=[{"uses":"owner/action@v1"},{"uses":"owner/action@v1"}]))
    output=tmp_path/"output.json"
    main(["cicd-workflow-review","--input",str(source),"--out",str(output),"--authorized"])
    assert json.loads(output.read_text())["input_sha256"] == report["input_sha256"]
    sarif=export_sarif(output)
    results=sarif["runs"][0]["results"]
    assert len(results) == 2 and all("locations" not in r for r in results)
    assert results[0]["partialFingerprints"] != results[1]["partialFingerprints"]


def test_contract_record_limits():
    data={"schema_version":1,"records":[{"id":k+str(i),"skill":"offensive-"+k,"observations":dict.fromkeys(fields,None)} for k,fields in PROFILES.items() for i in range(10)]}
    assert len(review_evidence(data)["records"]) == 20
    data["records"].append({**data["records"][0],"id":"extra"})
    with pytest.raises(ValueError):
        review_evidence(data)
