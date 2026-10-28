import json

import pytest

from hunterqa.assessment_evidence import compare_assessments, dashboard_evidence, load_assessment
from hunterqa.engagement import ENGINE
from hunterqa.cli import main


@pytest.fixture
def reports(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    baseline = {"schema_version": 1, "engine": ENGINE, "plan_sha256": "a" * 64,
                "policy_sha256": "b" * 64, "requests": 1, "stopped": False,
                "review_required": True, "claims": {"verified_vulnerabilities": 0,
                "confirmed_zero_days": 0, "cve_ids_created": 0},
                "observations": [{"mode": "observe", "target_sha256": "c" * 64,
                "verification": "unverified_observation", "status": 200, "body_sha256": "d" * 64}]}
    first, second = tmp_path / "first.json", tmp_path / "second.json"
    first.write_text(json.dumps(baseline))
    second.write_text(json.dumps(baseline))
    return first, second


def change(path, callback):
    data = json.loads(path.read_text())
    callback(data)
    path.write_text(json.dumps(data))


def test_comparison_reports_changes_without_vulnerability_claims(reports):
    first, second = reports
    change(second, lambda d: d["observations"][0].update(status=403, body_sha256="e" * 64))
    result = compare_assessments(first, second)
    assert result["status_changes"] == 1
    assert result["body_changes"] == 1
    assert result["network_requests"] == 0
    assert result["review_required"] is True
    assert result["coverage_equal"] is True


def test_missing_evidence_is_unknown_not_unchanged(reports):
    first, second = reports
    def partial(data):
        data["requests"] = 0
        data["stopped"] = True
        data["observations"][0].pop("status")
        data["observations"][0].pop("body_sha256")
        data["observations"][0]["outcome"] = "stopped"
    change(second, partial)
    result = compare_assessments(first, second)
    assert result["comparisons"][0]["status_changed"] is None
    assert result["comparisons"][0]["body_changed"] is None
    assert result["second_stopped"] is True


@pytest.mark.parametrize("field", ["plan_sha256", "policy_sha256"])
def test_cross_plan_or_policy_comparison_rejected(reports, field):
    first, second = reports
    change(second, lambda d: d.update({field: "f" * 64}))
    with pytest.raises(ValueError, match="same exact"):
        compare_assessments(first, second)


def test_reordered_or_replaced_targets_are_rejected(reports):
    first, second = reports
    change(second, lambda d: d["observations"][0].update(target_sha256="f" * 64))
    with pytest.raises(ValueError, match="identities"):
        compare_assessments(first, second)


@pytest.mark.parametrize("mutate", [lambda d: d.update(requests=True), lambda d: d.update(stopped="false"),
    lambda d: d["claims"].update(confirmed_zero_days=1), lambda d: d["observations"][0].update(mode=[]),
    lambda d: d["observations"][0].update(status=True), lambda d: d["observations"][0].update(status="private data"),
    lambda d: d["observations"][0].update(target_sha256="secret"),
    lambda d: d["observations"][0].update(authentication="confirmed")])
def test_malformed_or_overclaiming_reports_fail_closed(reports, mutate):
    first, _ = reports
    change(first, mutate)
    with pytest.raises(ValueError):
        load_assessment(first)
    assert dashboard_evidence(first)["status"] == "unavailable_or_invalid"


def test_dashboard_never_displays_unrecognized_report_text(reports, app, client):
    first, second = reports
    change(second, lambda d: d.update(secret="private-password", limitations="<script>untrusted</script>"))
    app.config.update(ENGAGEMENT_REPORT_PATH=str(second), ENGAGEMENT_BASELINE_PATH=str(first))
    response = client.get("/assessments?url=https://outside.example.test&run=true")
    assert response.status_code == 200
    assert b"Recorded observations" in response.data
    assert b"Baseline comparison" in response.data
    assert b"private-password" not in response.data
    assert b"<script>untrusted" not in response.data
    assert "private-password" not in json.dumps(dashboard_evidence(second, first))


def test_comparison_cli_writes_private_create_only_output(reports):
    first, second = reports
    out = first.parent / "comparison.json"
    args = ["engagement-compare", "--first", str(first), "--second", str(second), "--out", str(out)]
    main(args)
    assert json.loads(out.read_text())["network_requests"] == 0
    with pytest.raises(FileExistsError):
        main(args)
