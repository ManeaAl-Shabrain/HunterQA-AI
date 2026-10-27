import json

from hunterqa import doctor
from hunterqa.cli import main


def test_read_only_doctor_and_secret_redaction(tmp_path, monkeypatch):
    root = tmp_path / "approved"
    root.mkdir()
    project = root / "source"
    project.mkdir()
    rules = tmp_path / "semgrep.yml"
    rules.write_text("rules: []\n")
    monkeypatch.setattr(doctor.shutil, "which", lambda cmd: "/usr/bin/semgrep")
    secret = "very-secret-private-session-key-example-value"
    data = doctor.run_diagnostics(
        project=str(project), rules=rules,
        environment={"HUNTERQA_APPROVED_ROOTS": str(root),
                     "HUNTERQA_SECRET_KEY": secret},
    )
    assert data["overall"] == "ready"
    assert data["source_code_executed"] is False
    assert data["changes_made"] is False
    assert data["remote_network_access"] is False
    assert secret not in json.dumps(data)
    assert str(root) not in json.dumps(data)
    assert (root / "source").is_dir()


def test_project_outside_scope_fails(tmp_path, monkeypatch):
    approved = tmp_path / "approved"
    approved.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    monkeypatch.setattr(doctor.shutil, "which", lambda cmd: "semgrep")
    result = doctor.run_diagnostics(
        project=str(outside), rules=rules,
        environment={"HUNTERQA_APPROVED_ROOTS": str(approved)},
    )
    assert any(r["name"] == "project_scope" and r["status"] == "fail"
               for r in result["checks"])


def test_ollama_never_contacted_without_opt_in(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "probe_local_ollama",
                        lambda: (_ for _ in ()).throw(AssertionError("Unexpected call")))
    result = doctor.run_diagnostics(
        rules=tmp_path / "missing.yml",
        environment={},
    )
    assert next(c for c in result["checks"] if c["name"] == "ollama_model")["status"] == "skipped"


def test_ollama_optional_probe(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "probe_local_ollama",
                        lambda: {"qwen2.5-coder:3b"})
    result = doctor.run_diagnostics(
        rules=tmp_path / "missing.yml",
        check_ollama=True, environment={},
    )
    assert next(c for c in result["checks"] if c["name"] == "ollama_model")["status"] == "ok"


def test_doctor_cli_json(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "run_diagnostics", lambda **kwargs: {
        "overall": "ready", "checks": [], "summary": {},
    })
    main(["doctor", "--json"])
    assert json.loads(capsys.readouterr().out)["overall"] == "ready"
