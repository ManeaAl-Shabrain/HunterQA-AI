"""Owned synthetic source fixtures; no target services or inspected-code execution."""
import json

import pytest

from hunterqa.cli import main
from hunterqa.web_review import catalog, review_project


CASES = (
    ("sqli", 'cursor.execute(f"SELECT x FROM records WHERE id={value}")', 'cursor.execute("SELECT x FROM records WHERE id=?", (value,))'),
    ("xss", 'from markupsafe import Markup as M\nM(user_html)', 'from markupsafe import Markup\nMarkup("<b>fixed</b>")'),
    ("ssrf", 'import requests as r\nr.get(user_url)', 'import requests\nrequests.get("https://fixed.example")'),
    ("ssti", 'from flask import render_template_string as render\nrender(template)', 'from flask import render_template_string\nrender_template_string("Hello {{ name }}", name=user_name)'),
    ("xxe", 'from lxml import etree\netree.XMLParser(resolve_entities=True)', 'from lxml import etree\netree.XMLParser(resolve_entities=False)'),
    ("file-upload", 'upload.save(upload.filename)', 'upload.save(generated_storage_name)'),
    ("rce", 'import subprocess\nsubprocess.run(command, shell=True)', 'import subprocess\nsubprocess.run(["fixed-tool", argument], shell=False)'),
    ("deserialization", 'import pickle as p\np.loads(user_blob)', 'import json\njson.loads(user_blob)'),
    ("open-redirect", 'from flask import redirect\nredirect(destination)', 'from flask import redirect\nredirect("/home")'),
    ("graphql", 'from ariadne.asgi import GraphQL\nGraphQL(schema, introspection=True)', 'from ariadne.asgi import GraphQL\nGraphQL(schema, introspection=False)'),
)


@pytest.mark.parametrize("skill,positive,negative", CASES)
def test_positive_and_negative_syntax_controls(tmp_path, skill, positive, negative):
    (tmp_path / "positive.py").write_text(positive, encoding="utf-8")
    (tmp_path / "negative.py").write_text(negative, encoding="utf-8")
    report = review_project(tmp_path)
    assert [(f["skill"], f["file_path"]) for f in report["findings"]] == [("offensive-" + skill, "positive.py")]
    assert report["files_parsed"] == 2
    assert report["real_world_effectiveness"] == "unverified"
    assert not report["all_skills_automated"]


def test_full_catalog_has_distinct_manual_states(tmp_path):
    rows = catalog()
    assert len(rows) == len({r["id"] for r in rows}) == 16
    manual = {r["id"] for r in rows if r["implementation"] == "guided-review-only"}
    assert manual == {"offensive-" + key for key in ("idor", "race-condition", "request-smuggling", "parameter-pollution", "waf-bypass", "business-logic")}
    report = review_project(tmp_path)
    assert len(report["skills"]) == 16
    assert all(r["review_status"] == "manual-review-required" for r in report["skills"] if r["id"] in manual)


def test_source_not_executed_and_no_literal_secrets_exported(tmp_path):
    sentinel = tmp_path / "executed"
    (tmp_path / "app.py").write_text(
        f'from pathlib import Path\nPath({str(sentinel)!r}).touch()\n'
        'import os\nos.system(user_value)\n'
        'SECRET = "DO-NOT-EXPORT-THIS-FIXTURE"\n'
        '# os.system(comment)\ntext = "os.system(literal)"\n', encoding="utf-8")
    report = review_project(tmp_path)
    assert not sentinel.exists()
    assert len(report["findings"]) == 1
    assert "DO-NOT-EXPORT-THIS-FIXTURE" not in json.dumps(report)
    assert len(report["source_receipts"][0]["sha256"]) == 64


def test_skipped_and_unsupported_sources_do_not_claim_safety(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(", encoding="utf-8")
    (tmp_path / "large.py").write_bytes(b" " * (128 * 1024 + 1))
    (tmp_path / "web.js").write_text("eval(userInput)", encoding="utf-8")
    (tmp_path / ".env.py").write_text("import os\nos.system(secret)", encoding="utf-8")
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "private.py").write_text("import pickle\npickle.loads(secret)", encoding="utf-8")
    report = review_project(tmp_path)
    assert report["files_examined"] == 2
    assert report["files_parsed"] == 0
    assert len(report["skipped"]) == 2
    assert not report["findings"]
    assert all(s["review_status"] != "passed" for s in report["skills"])


def test_bounded_results_and_deterministic_receipts(tmp_path, monkeypatch):
    import hunterqa.web_review as module
    monkeypatch.setattr(module, "MAX_FILES", 1)
    monkeypatch.setattr(module, "MAX_FINDINGS", 1)
    (tmp_path / "a.py").write_text("import os\nos.system(x)\nos.system(y)", encoding="utf-8")
    (tmp_path / "b.py").write_text("pass", encoding="utf-8")
    first = review_project(tmp_path)
    assert first == review_project(tmp_path)
    assert first["truncated"] and len(first["findings"]) == 1
    assert first["files_examined"] == 1


def test_requests_request_destination_and_keyword_arguments(tmp_path):
    (tmp_path / "app.py").write_text('import requests\nrequests.request("GET", url)\nrequests.request("GET", url=url)\nrequests.request(method, "https://fixed.example")\nfrom flask import redirect\nredirect(location=destination)', encoding="utf-8")
    findings = review_project(tmp_path)["findings"]
    assert [f["skill"] for f in findings] == ["offensive-ssrf", "offensive-ssrf", "offensive-open-redirect"]


def test_symlinked_source_excluded(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside.py")
    outside.write_text("import os\nos.system(user_input)", encoding="utf-8")
    try:
        (tmp_path / "linked.py").symlink_to(outside)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    assert review_project(tmp_path)["files_examined"] == 0


def test_cli_approval_scope_output_and_catalog(tmp_path, monkeypatch, capsys):
    main(["web-review-catalog"])
    assert len(json.loads(capsys.readouterr().out)["skills"]) == 16
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("import os\nos.system(value)", encoding="utf-8")
    output = tmp_path / "review.json"
    with pytest.raises(PermissionError):
        main(["web-source-review", "--project", str(source), "--out", str(output)])
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS", raising=False)
    monkeypatch.delenv("ZEROSCOPE_APPROVED_ROOTS", raising=False)
    with pytest.raises(ValueError):
        main(["web-source-review", "--project", str(source), "--out", str(output), "--authorized"])
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    args = ["web-source-review", "--project", str(source), "--out", str(output), "--authorized"]
    main(args)
    assert len(json.loads(output.read_text())["findings"]) == 1
    with pytest.raises(FileExistsError):
        main(args)


def test_scan_engine_integration_and_sarif(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from hunterqa.orchestrator import scan_local_source
    from hunterqa.sarif_export import export_sarif
    import hunterqa.orchestrator as orchestrator
    (tmp_path / "app.py").write_text("import pickle\npickle.loads(untrusted)", encoding="utf-8")
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []", encoding="utf-8")
    monkeypatch.setattr(orchestrator.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout='{"results": []}', stderr=""))
    report = scan_local_source(tmp_path, rules)
    assert report["engines"]["web_source_review"] == "partial"
    assert report["web_review"]["files_parsed"] == 1
    assert report["findings"][0]["skill"] == "offensive-deserialization"
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    sarif = export_sarif(path)
    assert sarif["runs"][0]["results"][0]["properties"]["verificationStatus"] == "unverified"
    assert sarif["runs"][0]["results"][0]["level"] == "note"


def test_dashboard_scan_persists_source_candidates(app, approved_root, monkeypatch):
    from types import SimpleNamespace
    from hunterqa.db import connect
    from hunterqa.scanner import ScanService
    import hunterqa.orchestrator as orchestrator
    source = approved_root / "demo"
    (source / "app.py").write_text("import pickle\npickle.loads(untrusted)", encoding="utf-8")
    monkeypatch.setattr(orchestrator.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout='{"results": []}', stderr=""))
    monkeypatch.setattr(ScanService, "_create_report", lambda self, rows: "Owned deterministic review summary")
    with connect(app.config["DATABASE"]) as db:
        project = db.execute("INSERT INTO projects(name, path) VALUES (?, ?)", ("owned", str(source))).lastrowid
        scan = db.execute("INSERT INTO scans(project_id) VALUES (?)", (project,)).lastrowid
    ScanService(app).run(scan)
    with connect(app.config["DATABASE"]) as db:
        assert db.execute("SELECT status FROM scans WHERE id=?", (scan,)).fetchone()[0] == "completed"
        row = db.execute("SELECT rule_id, code, message, verification_status FROM findings WHERE scan_id=?", (scan,)).fetchone()
    assert row["rule_id"] == "web-source.deserialization"
    assert row["code"] == ""  # Source snippets must stay private.
    assert "data-only" in row["message"]
    assert row["verification_status"] == "unverified"
