import json
import pytest
from hunterqa.engines.cve_intel import match_snapshot, run_cve_check, read_cve_report


def advisory():
    return [{"id": "OSV-EXAMPLE-1", "aliases": ["CVE-2025-12345"],
             "summary": "Test-only advisory",
             "affected": [{"package": {"ecosystem": "PyPI", "name": "demo-lib"},
                           "versions": ["1.2.3"]}]}]


def test_exact_match_without_confirmation():
    result = match_snapshot(
        [{"ecosystem": "PyPI", "name": "demo_lib", "version": "1.2.3", "source": "requirements.txt"}],
        advisory(), snapshot_sha256="a"*64)
    assert len(result["matches"]) == 1
    assert result["matches"][0]["cve_ids"] == ["CVE-2025-12345"]
    assert result["matches"][0]["confirmed_vulnerability"] is False


def test_no_match_for_other_version():
    result = match_snapshot(
        [{"ecosystem": "PyPI", "name": "demo-lib", "version": "2.0.0", "source": "requirements.txt"}], advisory())
    assert not result["matches"]


def test_unresolved_npm_constraint_is_not_claimed():
    result = match_snapshot(
        [{"ecosystem": "npm", "name": "demo-lib", "version": "^1.2.3", "source": "package.json"}], advisory())
    assert result["coverage"]["not_exactly_resolved"] == 1
    assert result["matches"] == []


def test_range_only_advisory_not_guessed():
    items = advisory()
    items[0]["affected"][0].pop("versions")
    items[0]["affected"][0]["ranges"] = [{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.3.0"}]}]
    result = match_snapshot(
        [{"ecosystem": "PyPI", "name": "demo-lib", "version": "1.2.3", "source": "requirements.txt"}], items)
    assert not result["matches"]
    assert result["coverage"]["related_advisories_without_explicit_versions"] == 1


def test_withdrawn_not_matched():
    items = advisory()
    items[0]["withdrawn"] = "2026-01-01T00:00:00Z"
    assert not match_snapshot([{"ecosystem":"PyPI","name":"demo-lib","version":"1.2.3"}],items)["matches"]


def test_scoped_cli_report(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    project = root / "code"
    project.mkdir()
    (project / "requirements.txt").write_text("demo_lib==1.2.3\n")
    snapshot = root / "osv.json"
    snapshot.write_text(json.dumps(advisory()))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    result = run_cve_check(project, snapshot)
    assert result["coverage"]["matched_advisory_records"] == 1
    assert result["claims"]["confirmed_vulnerabilities"] == 0
    assert len(result["snapshot_sha256"]) == 64


def test_unapproved_snapshot_rejected(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    snapshot = tmp_path / "outside.json"
    snapshot.write_text(json.dumps(advisory()))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    with pytest.raises(ValueError):
        run_cve_check(root, snapshot)


def test_dashboard_no_arbitrary_paths(client):
    response = client.get("/cve-intelligence?path=/etc/passwd")
    assert response.status_code == 200
    assert b"CVE Intelligence" in response.data
