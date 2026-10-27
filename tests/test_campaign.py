import json
import pytest
from hunterqa import campaign


@pytest.fixture
def paths(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    project = root / "project"
    project.mkdir()
    (project / "demo.py").write_text("x = 1\n")
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    return root, project


def test_campaign_requires_authorization(paths):
    root, project = paths
    with pytest.raises(PermissionError):
        campaign.run_campaign(project, root / "one", authorized=False)
    assert not (root / "one").exists()


def test_campaign_outputs_and_fail_closed_stage(paths, monkeypatch):
    root, project = paths
    monkeypatch.setattr(campaign, "scan_local_source", lambda *a, **kw: {
        "findings": [], "dependencies": [], "engines": {"semgrep": "completed"}
    })
    monkeypatch.setattr(campaign, "build_trust_graph", lambda *a: {
        "review_paths": [], "nodes": [], "edges": []
    })
    result = campaign.run_campaign(project, root / "one", authorized=True)
    assert result["stages"]["scan"]["status"] == "completed"
    assert result["stages"]["triage"]["status"] == "completed"
    assert result["summary"]["zero_days_confirmed"] == 0
    assert (root / "one" / "manifest.json").is_file()
    assert (root / "one" / "triage.json").is_file()
    with pytest.raises(ValueError):
        campaign.run_campaign(project, root / "one", authorized=True)


def test_campaign_optional_ai_failure_recorded(paths, monkeypatch):
    root, project = paths
    monkeypatch.setattr(campaign, "scan_local_source", lambda *a, **kw: {
        "findings": [], "dependencies": []
    })
    monkeypatch.setattr(campaign, "analyze_local",
                        lambda *a, **kw: (_ for _ in ()).throw(TimeoutError()))
    result = campaign.run_campaign(
        project, root / "ai-run", authorized=True, include_graph=False, include_ai=True,
    )
    assert result["stages"]["ai"]["status"] == "failed"
    assert result["stages"]["ai"]["error_type"] == "TimeoutError"
    assert result["stages"]["triage"]["status"] == "completed"


def test_replay_scope_denied_before_output_creation(paths):
    root, project = paths
    lab = root / "lab"
    lab.mkdir()
    binary = lab / "executable"
    binary.write_bytes(b"program")
    crash_dir = lab / "crashes"
    crash_dir.mkdir()
    with pytest.raises(ValueError):
        campaign.run_campaign(
            project, root / "outside-lab", authorized=True,
            replay_lab=lab, replay_binary=binary, replay_crashes=crash_dir,
        )
    assert not (root / "outside-lab").exists()


def test_reject_unapproved_output(paths, tmp_path):
    _, project = paths
    with pytest.raises(ValueError):
        campaign.run_campaign(project, tmp_path / "outside", authorized=True)
    assert not (tmp_path / "outside").exists()
