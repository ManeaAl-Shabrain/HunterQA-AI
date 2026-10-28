import hashlib
import json
import os
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.external_evidence import import_external
from hunterqa.research_workspace import append_note, create_workspace, resume_workspace
from hunterqa.sarif_export import export_sarif
from tools.action_review import run_action


@pytest.fixture
def private(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"program": "Owned research fixture", "platform": "private",
        "authorization_reference": "Owned research fixture approval", "acknowledged_authorization": True,
        "allowed_hosts": ["owned.example.test"], "allowed_paths": ["/app"],
        "excluded_paths": ["/app/admin"], "methods": ["GET", "HEAD"], "max_requests": 4,
        "interval_seconds": 0.5, "allowed_ports": [443]}))
    return tmp_path, profile


def test_workspace_preserves_research_context_without_execution(private):
    root, profile = private
    workspace = root / "research"
    create_workspace(profile, workspace, ["api-authorization", "ai-output-review"], authorized=True)
    evidence = root / "private-evidence.txt"
    evidence.write_text("private response evidence")
    append_note(profile, workspace, "observation", "Expected denial differs from the captured fixture.",
                evidence=evidence, authorized=True)
    append_note(profile, workspace, "negative-result", "The permitted control behaves as expected.", authorized=True)
    append_note(profile, workspace, "next-step", "Have another analyst inspect impact.", authorized=True)
    result = resume_workspace(workspace)
    assert result["event_count"] == 3
    assert result["counts"]["negative-result"] == 1
    assert result["network_requests"] == 0 and result["execution_resumed"] is False
    assert result["recent_notes"][0]["evidence_sha256"] == hashlib.sha256(evidence.read_bytes()).hexdigest()
    assert "private response evidence" not in json.dumps(result)
    if os.name == "posix":
        assert workspace.stat().st_mode & 0o777 == 0o700
        assert (workspace / "journal.jsonl").stat().st_mode & 0o777 == 0o600


def test_workspace_requires_authorization_and_known_playbooks(private):
    root, profile = private
    with pytest.raises(PermissionError):
        create_workspace(profile, root / "denied", ["api-authorization"])
    assert not (root / "denied").exists()
    for selection in (["shell-runner"], ["api-authorization", "api-authorization"], []):
        with pytest.raises(ValueError):
            create_workspace(profile, root / "denied", selection, authorized=True)


def test_workspace_tampering_and_incomplete_writes_fail_closed(private):
    root, profile = private
    workspace = root / "research"
    create_workspace(profile, workspace, ["source-boundaries"], authorized=True)
    append_note(profile, workspace, "hypothesis", "A source pattern requires validation.", authorized=True)
    journal = workspace / "journal.jsonl"
    raw = journal.read_bytes()
    row = json.loads(raw)
    row["summary"] = "changed without updating the journal hash"
    journal.write_text(json.dumps(row) + "\n")
    with pytest.raises(ValueError, match="hash mismatch"):
        resume_workspace(workspace)
    journal.write_bytes(raw.rstrip(b"\n"))
    with pytest.raises(ValueError, match="Incomplete"):
        append_note(profile, workspace, "next-step", "Never append to partial evidence.", authorized=True)


def test_workspace_profile_changes_and_existing_lock_are_rejected(private):
    root, profile = private
    workspace = root / "research"
    create_workspace(profile, workspace, ["source-boundaries"], authorized=True)
    lock = workspace / "append.lock"
    lock.write_text("another writer")
    with pytest.raises(FileExistsError):
        append_note(profile, workspace, "observation", "Do not race another writer.", authorized=True)
    assert lock.read_text() == "another writer"
    lock.unlink()
    profile.write_text(profile.read_text() + " ")
    with pytest.raises(ValueError, match="profile changed"):
        append_note(profile, workspace, "observation", "Changed scope needs new context.", authorized=True)
    assert (workspace / "journal.jsonl").read_bytes() == b""


@pytest.mark.parametrize("kind,summary", [("validated", "not a supported state"), ("observation", "line\nbreak"),
                                         ("next-step", ""), ("hypothesis", "x" * 1001)])
def test_workspace_cannot_promote_notes_to_findings_or_commands(private, kind, summary):
    root, profile = private
    create_workspace(profile, root / "research", ["ai-output-review"], authorized=True)
    with pytest.raises(ValueError):
        append_note(profile, root / "research", kind, summary, authorized=True)


def test_nuclei_import_is_scoped_deduplicated_and_omits_raw_material(private, monkeypatch):
    root, profile = private
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **kw: pytest.fail("DNS during offline import"))
    row = {"template-id": "review-fixture", "type": "http", "matched-at": "https://owned.example.test/app/items?token=secret-token",
           "info": {"name": "secret-name", "severity": "high", "classification": {"cwe-id": ["CWE-79"]}},
           "request": "Authorization: private-password", "response": "private response", "extracted-results": ["secret-value"]}
    file = root / "nuclei.jsonl"
    file.write_text("\n".join(json.dumps(item) for item in [row, row, {**row, "matched-at": "https://outside.example.test/app"}]))
    result = import_external(profile, file, "nuclei", authorized=True)
    assert result["summary"] == {"received": 3, "accepted": 1, "skipped": 1, "duplicates": 1}
    assert result["findings"][0]["cwe"] == "CWE-79"
    assert result["findings"][0]["confirmed_vulnerability"] is False
    serialized = json.dumps(result)
    for text in ("owned.example.test", "secret-token", "private-password", "private response", "secret-name", "secret-value"):
        assert text not in serialized


def test_zap_import_uses_instances_and_keeps_source_level_unverified(private):
    root, profile = private
    file = root / "zap.json"
    file.write_text(json.dumps({"site": [{"alerts": [{"pluginid": "10021", "riskcode": "2", "cweid": "16",
        "desc": "private detail", "instances": [{"uri": "https://owned.example.test/app", "attack": "payload"},
        {"uri": "https://owned.example.test/app/admin"}]}]}]}))
    result = import_external(profile, file, "zap", authorized=True)
    assert result["summary"]["accepted"] == 1 and result["summary"]["skipped"] == 1
    assert result["findings"][0]["source_severity"] == "medium"
    assert "private detail" not in json.dumps(result) and "payload" not in json.dumps(result["findings"])


def test_external_import_rejects_unauthorized_and_malformed_inputs(private):
    root, profile = private
    file = root / "nuclei.jsonl"
    file.write_text('{"template-id":"one","template-id":"two"}\n')
    with pytest.raises(PermissionError):
        import_external(profile, file, "nuclei")
    with pytest.raises(ValueError, match="Duplicate"):
        import_external(profile, file, "nuclei", authorized=True)


@pytest.mark.parametrize("path", ["/private/home.py", "../outside.py", "C:\\private\\source.py", "https://private.test/x", "src/./a.py"])
def test_sarif_omits_unsafe_locations_and_untrusted_prose(private, path):
    root, _ = private
    file = root / "scan.json"
    file.write_text(json.dumps({"findings": [{"rule_id": "sample.rule", "file_path": path,
        "title": "secret title", "message": "secret message", "code": "private code", "severity": "ERROR",
        "line_start": 7, "confirmed_vulnerability": True}]}))
    result = export_sarif(file)
    finding = result["runs"][0]["results"][0]
    assert "locations" not in finding
    assert finding["properties"]["verificationStatus"] == "unverified"
    assert "private code" not in json.dumps(result) and "secret message" not in json.dumps(result)
    assert result["version"] == "2.1.0"


def test_sarif_relative_unicode_paths_are_encoded_and_rules_deduplicated(private):
    root, _ = private
    file = root / "scan.json"
    item = {"rule_id": "sample.rule", "file_path": "src/مراجعة name.py", "severity": "WARNING", "line_start": 4}
    file.write_text(json.dumps({"findings": [item, item]}))
    result = export_sarif(file)["runs"][0]
    assert len(result["tool"]["driver"]["rules"]) == 1
    uri = result["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("src/%D9%85") and uri.endswith("%20name.py") and uri.isascii()


def test_cli_research_and_sarif_workflow(private, capsys):
    root, profile = private
    main(["research-playbooks"])
    assert len(json.loads(capsys.readouterr().out)["playbooks"]) == 10
    main(["research-init", "--profile", str(profile), "--out-dir", str(root / "research"),
          "--playbook", "pipeline-review", "--authorized"])
    capsys.readouterr()
    main(["research-note", "--profile", str(profile), "--workspace", str(root / "research"),
          "--kind", "negative-result", "--summary", "Control did not reproduce the hypothesis.", "--authorized"])
    capsys.readouterr()
    main(["research-resume", "--workspace", str(root / "research")])
    assert json.loads(capsys.readouterr().out)["event_count"] == 1
    file = root / "empty.json"
    file.write_text('{"findings":[]}')
    main(["report-sarif", "--file", str(file), "--out", str(root / "empty.sarif")])
    assert json.loads((root / "empty.sarif").read_text())["version"] == "2.1.0"


def action_env(tmp_path):
    repo, temporary = tmp_path / "repo", tmp_path / "runner"
    repo.mkdir()
    temporary.mkdir()
    output = tmp_path / "output.txt"
    output.touch()
    return {"HUNTERQA_ACTION_AUTHORIZED": "true", "GITHUB_WORKSPACE": str(repo),
            "RUNNER_TEMP": str(temporary), "GITHUB_OUTPUT": str(output)}


def test_action_writes_sarif_without_exporting_source_and_uses_label_gate(tmp_path):
    env = action_env(tmp_path)
    def scanner(project, rules):
        assert project == (tmp_path / "repo").resolve()
        return {"findings": [{"rule_id": "sample.rule", "severity": "ERROR", "file_path": "sample.py", "line_start": 1,
                              "code": "private source", "message": "private value"}]}
    assert run_action(env, scanner=scanner) == 0
    content = Path(env["GITHUB_OUTPUT"]).read_text()
    sarif = Path(next(line.split("=", 1)[1] for line in content.splitlines() if line.startswith("sarif_path=")))
    assert "candidate_count=1" in content
    assert "private source" not in sarif.read_text()
    env["HUNTERQA_ACTION_FAIL_ON"] = "error"
    assert run_action(env, scanner=scanner) == 3


@pytest.mark.parametrize("path", ["../outside", "/etc", "C:\\Windows", "x\ncommand"])
def test_action_rejects_scope_escape_before_scanning(tmp_path, path):
    env = action_env(tmp_path)
    env["HUNTERQA_ACTION_PROJECT"] = path
    with pytest.raises(ValueError):
        run_action(env, scanner=lambda *a: pytest.fail("Scanned an invalid target"))


def test_action_requires_explicit_acknowledgment(tmp_path):
    env = action_env(tmp_path)
    env["HUNTERQA_ACTION_AUTHORIZED"] = "false"
    with pytest.raises(PermissionError):
        run_action(env, scanner=lambda *a: pytest.fail("Unauthorized scan"))


def test_playbook_page_is_original_read_only_data(client):
    response = client.get("/playbooks?execute=true")
    assert response.status_code == 200
    assert response.data.count(b'<details class="research-entry">') == 10
    assert b"do not run tools" in response.data
