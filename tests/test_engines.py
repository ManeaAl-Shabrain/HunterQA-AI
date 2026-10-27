import json
from pathlib import Path
from hunterqa.engines.config_audit import audit_project
from hunterqa.engines.dependencies import inventory, match_local_advisories
from hunterqa.engines.openapi import audit_openapi
from hunterqa.engines.sanitizers import parse_sanitizer_log
from hunterqa.engines.sarif import import_sarif
from hunterqa.orchestrator import deduplicate


def test_config_audit(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:latest\nUSER root\n")
    findings = audit_project(tmp_path)
    assert any(x["rule_id"] == "hunterqa.docker.root-user" for x in findings)
    assert any(x["rule_id"] == "hunterqa.docker.latest-tag" for x in findings)


def test_config_ignores_symlink_escape(tmp_path):
    outside = tmp_path.parent / "external-Dockerfile"
    outside.write_text("USER root\n")
    (tmp_path / "Dockerfile").symlink_to(outside)
    assert audit_project(tmp_path) == []


def test_inventory_and_exact_offline_match(tmp_path):
    (tmp_path / "requirements.txt").write_text("demo==1.2.3\nother>=2.0\n")
    inv = inventory(tmp_path)
    assert len(inv) == 1 and inv[0]["name"] == "demo"
    matched = match_local_advisories(inv, [{"ecosystem": "PyPI", "package": "demo", "version": "1.2.3", "id": "TEST-1"}])
    assert len(matched) == 1 and matched[0]["verification_status"] == "requires_human_review"


def test_openapi_missing_declared_auth_is_hint(tmp_path):
    (tmp_path / "openapi.json").write_text(json.dumps({"openapi": "3.0.0", "paths": {"/orders": {"get": {"responses": {"200": {}}}}}}))
    findings = audit_openapi(tmp_path)
    assert len(findings) == 1 and findings[0]["severity"] == "INFO"


def test_parse_asan_and_absence():
    log = "ERROR: AddressSanitizer: heap-use-after-free\nSUMMARY: AddressSanitizer: heap-use-after-free /lab/uaf_test.c:14:27 in main"
    parsed = parse_sanitizer_log(log)
    assert parsed["cwe_candidate"] == "CWE-416" and parsed["evidence_confirmed"]
    assert parse_sanitizer_log("SIGABRT") ["cwe_candidate"] is None


def test_read_only_sarif(tmp_path):
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps({"runs": [{"results": [{"ruleId": "rule-1", "message": {"text": "review it"}}]}]}))
    rows = import_sarif(path)
    assert rows[0]["rule_id"] == "rule-1" and rows[0]["verification_status"] == "unverified"


def test_deduplication():
    item = {"rule_id": "a", "file_path": "x", "line_start": 1}
    assert len(deduplicate([item, item])) == 1
