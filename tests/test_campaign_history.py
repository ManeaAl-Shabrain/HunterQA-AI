import hashlib
import json

from hunterqa.engines.campaign_history import (
    read_campaign_history, compare_campaigns, public_history,
)


def make_campaign(root, name, project, title):
    folder = root / name
    folder.mkdir()
    triage = {
        "engine": "unified_evidence_triage",
        "findings": [{"source": "scan", "file": "demo.py", "line": 1, "title": title}],
    }
    raw = (json.dumps(triage) + "\n").encode()
    (folder / "triage.json").write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    stages = {
        name: {"status": "skipped"}
        for name in ("scan", "graph", "ai", "replay", "sanitizer", "triage")
    }
    stages["triage"] = {"status": "completed", "sha256": digest}
    manifest = {
        "engine": "hunterqa_authorized_local_campaign",
        "schema_version": 1,
        "project": str(project),
        "started_at": "2026-10-28T10:00:00Z",
        "finished_at": "2026-10-28T10:01:00Z",
        "stages": stages,
        "artifacts": {"triage": {"file": "triage.json", "sha256": digest}},
        "summary": {"research_records": 1},
    }
    (folder / "manifest.json").write_text(json.dumps(manifest))
    return folder


def test_history_and_comparison(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    make_campaign(root, "campaign-one", "local-project", "Finding A")
    make_campaign(root, "campaign-two", "local-project", "Finding B")
    history = read_campaign_history(root, [root])
    assert len(history["campaigns"]) == 2
    assert all(x["integrity"] == "hashes_match" for x in history["campaigns"])
    result = compare_campaigns(history, "campaign-one", "campaign-two")
    assert result["status"] == "ready"
    assert result["candidate_keys_added"] == 1
    assert result["candidate_keys_missing"] == 1
    assert "_records" not in public_history(history)["campaigns"][0]


def test_tampered_artifact_fails_verification(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    folder = make_campaign(root, "campaign-one", "local-project", "Finding A")
    (folder / "triage.json").write_text('{"changed":true}')
    history = read_campaign_history(root, [root])
    assert history["campaigns"][0]["integrity"] == "verification_failed"


def test_symlink_campaign_ignored(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    make_campaign(outside, "fake-run", "local-project", "Finding A")
    (root / "fake-run").symlink_to(outside / "fake-run", target_is_directory=True)
    history = read_campaign_history(root, [root])
    assert history["campaigns"] == []


def test_route_renders_and_comparison(client, app, tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    make_campaign(root, "campaign-one", "local-project", "Finding A")
    make_campaign(root, "campaign-two", "local-project", "Finding B")
    app.config["CAMPAIGN_HISTORY_ROOT"] = str(root)
    app.config["APPROVED_ROOTS"] = [str(root)]
    response = client.get("/campaigns?left=campaign-one&right=campaign-two")
    assert response.status_code == 200
    assert b"Campaign History" in response.data
    assert b"Added candidate keys" in response.data
    assert b"Finding A" not in response.data


def test_different_projects_not_compared(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    make_campaign(root, "one", "project-a", "A")
    make_campaign(root, "two", "project-b", "B")
    result = compare_campaigns(read_campaign_history(root, [root]), "one", "two")
    assert result["status"] == "different_projects"
