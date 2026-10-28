from pathlib import Path
import json
import pytest

import hunterqa.bounty_campaign as bc


@pytest.fixture
def setup_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    project = tmp_path / "project"
    project.mkdir()
    profile = tmp_path / "scope.json"
    profile.write_text(json.dumps({
        "program": "My local lab", "platform": "local-lab",
        "authorization_reference": "Internal lab authorization #123",
        "acknowledged_authorization": True,
        "allowed_hosts": ["app.example.test"], "methods": ["HEAD"],
        "max_requests": 3, "interval_seconds": 0.5,
    }))
    targets = tmp_path / "targets.txt"
    targets.write_text("https://app.example.test/\n")
    return project, profile, targets, tmp_path


def test_scope_failure_prevents_running_local_or_web(setup_env, monkeypatch):
    project, profile, targets, root = setup_env
    targets.write_text("https://app.example.test/\nhttps://wrong.test/\n")
    started = []
    monkeypatch.setattr(bc, "run_campaign", lambda *a, **kw: started.append(True))
    with pytest.raises(ValueError):
        bc.run_bounty_campaign(
            project, root / "new", profile, targets_path=targets,
            authorized=True, with_web=True
        )
    assert started == []
    assert not (root / "new").exists()


def test_integrated_local_cve_har_and_web_are_human_review_only(setup_env, monkeypatch):
    project, profile, targets, root = setup_env
    snapshot = root / "osv.json"
    snapshot.write_text('{"vulns":[]}')
    har = root / "capture.har"
    har.write_text('{"log":{"entries":[]}}')
    def fake_local(project, out_dir, **kwargs):
        Path(out_dir).mkdir()
        return {"output_directory": str(out_dir),
                "summary": {"failed_stages": 0, "research_records": 2},
                "stages": {"scan": {"status": "completed"}}}
    monkeypatch.setattr(bc, "run_campaign", fake_local)
    monkeypatch.setattr(bc, "run_cve_check", lambda *_: {
        "matches": [{"advisory_id": "GHSA-test"}],
        "cve_groups": [{"cve_id": "CVE-2025-12345"}]})
    monkeypatch.setattr(bc, "import_har", lambda *a, **kw: {
        "observations": [{"status": 200}], "findings": []})
    monkeypatch.setattr(bc, "assess", lambda *a, **kw: {
        "observations": [{"status": 200}], "findings": [{"id": "candidate"}]})
    result = bc.run_bounty_campaign(
        project, root / "engagement", profile, authorized=True,
        with_ai=True, with_web=True, targets_path=targets,
        snapshot_path=snapshot, har_path=har
    )
    summary = result["summary"]
    assert summary["source_candidates"] == 2
    assert summary["unique_cve_groups"] == 1
    assert summary["http_observations"] == 2
    assert summary["web_candidate_observations"] == 1
    assert result["claims"]["confirmed_zero_days"] == 0
    assert (root / "engagement/engagement.json").is_file()
    assert (root / "engagement/bounty_cve.json").is_file()


def test_with_web_requires_explicit_list(setup_env):
    project, profile, targets, root = setup_env
    with pytest.raises(ValueError, match="requires"):
        bc.run_bounty_campaign(
            project, root / "unused", profile, authorized=True,
            with_web=True
        )
    assert not (root / "unused").exists()


def test_engagement_requires_authorization(setup_env):
    project, profile, targets, root = setup_env
    with pytest.raises(PermissionError):
        bc.run_bounty_campaign(project, root / "out", profile)
