"""Offline-only HEAD reproducibility checks; tests never send HTTP requests."""
import hashlib
import json

import pytest

from hunterqa.repeatability_v12 import compare_head_replays


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    policy = tmp_path / "scope.json"
    policy.write_text(json.dumps({
        "program": "Owned HEAD comparisons", "platform": "local-lab",
        "authorization_reference": "Owned offline HEAD lab fixture",
        "acknowledged_authorization": True, "allowed_hosts": ["app.example.test"],
        "methods": ["HEAD"], "max_requests": 2,
    }))
    raw = {
        "engine": "hunterqa_v12_controlled_head_replay",
        "program": "Owned HEAD comparisons", "platform": "local-lab",
        "policy_sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
        "source_evidence_sha256": "a" * 64,
        "comparisons": [
            {"target_hash": "b" * 24, "baseline_status": 200,
             "observed_status": 200, "confirmed_vulnerability": False},
            {"target_hash": "c" * 24, "baseline_status": 302,
             "observed_status": 301, "confirmed_vulnerability": False},
        ],
    }
    first = tmp_path / "head-001.json"
    second = tmp_path / "head-002.json"
    first.write_text(json.dumps(raw))
    raw["comparisons"][1]["observed_status"] = 302
    second.write_text(json.dumps(raw, indent=2))
    return tmp_path, policy, first, second


def test_repeatability_comparison_is_offline_and_never_confirms_vuln(files, monkeypatch):
    root, policy, a, b = files
    import socket
    monkeypatch.setattr(socket, "create_connection",
        lambda *args, **kwargs: pytest.fail("Unexpected outbound network request"))
    report = compare_head_replays(policy, a, b, authorized=True)
    assert report["summary"] == {
        "matched_targets": 2, "stable_status_observations": 1,
        "different_status_observations": 1,
        "confirmed_vulnerabilities": 0, "confirmed_zero_days": 0,
    }
    assert len(report["checks"]) == 2
    assert all(x["confirmed_vulnerability"] is False for x in report["checks"])
    assert "https://" not in json.dumps(report)
    assert report["source_evidence_sha256"] == "a" * 64


@pytest.mark.parametrize("field,new_value,expected", [
    ("program", "Another lab", "authorized program"),
    ("policy_sha256", "f" * 64, "authorized program"),
    ("source_evidence_sha256", "f" * 64, "different sanitized HAR"),
])
def test_changed_provenance_fail_closed(files, field, new_value, expected):
    root, policy, a, b = files
    data = json.loads(b.read_text())
    data[field] = new_value
    b.write_text(json.dumps(data))
    with pytest.raises(ValueError, match=expected):
        compare_head_replays(policy, a, b, authorized=True)


def test_reject_duplicate_target_hash_in_same_run(files):
    root, policy, a, b = files
    data = json.loads(b.read_text())
    data["comparisons"].append(dict(data["comparisons"][0]))
    b.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="duplicate"):
        compare_head_replays(policy, a, b, authorized=True)


def test_reject_auto_confirmed_evidence_claim(files):
    root, policy, a, b = files
    data = json.loads(a.read_text())
    data["comparisons"][0]["confirmed_vulnerability"] = True
    a.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="nonconfirmed"):
        compare_head_replays(policy, a, b, authorized=True)


def test_reject_baseline_disagreement(files):
    root, policy, a, b = files
    data = json.loads(b.read_text())
    data["comparisons"][0]["baseline_status"] = 403
    b.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="Conflicting original"):
        compare_head_replays(policy, a, b, authorized=True)


def test_require_distinct_evidence_and_authorization(files):
    root, policy, a, b = files
    with pytest.raises(PermissionError):
        compare_head_replays(policy, a, b)
    with pytest.raises(ValueError, match="distinct"):
        compare_head_replays(policy, a, a, authorized=True)


def test_require_matching_targets(files):
    root, policy, a, b = files
    data = json.loads(b.read_text())
    data["comparisons"] = [{
        "target_hash": "d" * 24, "baseline_status": 200,
        "observed_status": 200, "confirmed_vulnerability": False,
    }]
    b.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="No shared"):
        compare_head_replays(policy, a, b, authorized=True)


def test_symlink_report_refused(files):
    root, policy, a, b = files
    link = root / "head-link.json"
    link.symlink_to(a)
    with pytest.raises(ValueError, match="Symlink"):
        compare_head_replays(policy, link, b, authorized=True)
