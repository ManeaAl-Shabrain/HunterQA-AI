import json
import socket
import sqlite3
import subprocess

import pytest

from hunterqa import lab_validation as lab
from hunterqa.cli import main


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return tmp_path / "run"


def test_owned_impact_and_parameterized_control_have_replayable_evidence(root, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No network or subprocess allowed")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    report = lab.validate_owned_sql(root, authorized=True)
    assert report["all_cases_matched"] and report["impact_demonstrated_in_owned_fixture"]
    assert len(report["cases"]) == 8
    assert (report["true_positives"], report["false_positives"], report["false_negatives"]) == (1, 0, 0)
    observations = json.loads((root / "observations.json").read_text())
    assert [r["id"] for r in observations if r["foreign_read"]] == ["literal-probe"]
    assert [r["rows"] for r in observations] == [0, 0, 1, 1, 0, 0, 1, 0]
    raw = (root / "validation.json").read_text() + (root / "observations.json").read_text()
    assert lab.FOREIGN not in raw and lab.OWN not in raw and lab.INPUTS["probe"] not in raw
    assert lab.verify_owned_sql(root)["passed"]
    assert report["network_requests"] == report["customer_findings_confirmed"] == 0
    with pytest.raises(FileExistsError):
        lab.validate_owned_sql(root, authorized=True)


def test_authorization_before_output_and_root_admission(root, monkeypatch):
    with pytest.raises(PermissionError):
        lab.validate_owned_sql(root)
    assert not root.exists()
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS")
    with pytest.raises(ValueError):
        lab.validate_owned_sql(root, authorized=True)
    assert not root.exists()


def test_missed_vulnerable_case_cannot_pass(root, monkeypatch):
    query = lab._query
    monkeypatch.setattr(lab, "_query", lambda db, mode, value: query(db, "bound", value))
    report = lab.validate_owned_sql(root, authorized=True)
    assert not report["all_cases_matched"] and not report["impact_demonstrated_in_owned_fixture"]
    assert report["false_negatives"] == 1
    assert not lab.verify_owned_sql(root)["passed"]


def test_false_positive_cases_cannot_pass(root, monkeypatch):
    monkeypatch.setattr(lab, "_query", lambda *args: ([(lab.FOREIGN,)], "a" * 64))
    report = lab.validate_owned_sql(root, authorized=True)
    assert report["false_positives"] == 7
    assert not report["all_cases_matched"] and not report["impact_demonstrated_in_owned_fixture"]


def test_database_writes_are_denied_after_seeding(root, monkeypatch):
    query = lab._query
    def check(db, mode, value):
        with pytest.raises(sqlite3.DatabaseError):
            db.execute("DELETE FROM records")
        return query(db, mode, value)
    monkeypatch.setattr(lab, "_query", check)
    assert lab.validate_owned_sql(root, authorized=True)["all_cases_matched"]


@pytest.mark.parametrize("field,value", [("rows", True), ("rows", 3),
    ("foreign_read", "true"), ("id", "unknown"), ("query_sha256", "g" * 64)])
def test_invalid_observation_fields_are_rejected(root, field, value):
    labels = lab._labels()
    observations = lab._observations(labels)
    observations[0][field] = value
    with pytest.raises(ValueError):
        lab._measure(labels, observations)


def test_modified_ground_truth_is_rejected(root):
    lab.validate_owned_sql(root, authorized=True)
    path = root / "ground-truth.json"
    labels = json.loads(path.read_text())
    labels["cases"][0]["expected_rows"] = 1
    path.write_text(json.dumps(labels))
    with pytest.raises(ValueError):
        lab.verify_owned_sql(root)


@pytest.mark.parametrize("field,value", [("all_cases_matched", False),
    ("observations_sha256", "a" * 64), ("fixture_source_sha256", "a" * 64),
    ("labels_sha256", "a" * 64), ("network_requests", 1),
    ("network_requests", False), ("customer_findings_confirmed", 1),
    ("real_world_effectiveness", "verified"), ("schema_version", True)])
def test_modified_report_is_rejected(root, field, value):
    lab.validate_owned_sql(root, authorized=True)
    path = root / "validation.json"
    report = json.loads(path.read_text())
    report[field] = value
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError):
        lab.verify_owned_sql(root)


def test_recomputed_receipts_cannot_hide_changed_observations_from_local_replay(root):
    lab.validate_owned_sql(root, authorized=True)
    path = root / "observations.json"
    rows = json.loads(path.read_text())
    rows[0]["query_sha256"] = "f" * 64
    path.write_text(json.dumps(rows))
    report_file = root / "validation.json"
    report = json.loads(report_file.read_text())
    report["observations_sha256"] = lab.digest(rows)
    report_file.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="replay"):
        lab.verify_owned_sql(root)


def test_cli_pass_and_failure_exit_codes(root, monkeypatch, capsys):
    main(["lab-sql-validation", "--out-dir", str(root), "--authorized"])
    assert json.loads(capsys.readouterr().out)["all_cases_matched"]
    main(["lab-sql-verify", "--run", str(root)])
    assert json.loads(capsys.readouterr().out)["passed"]
    monkeypatch.setattr(lab, "validate_owned_sql", lambda *a, **k: {"all_cases_matched": False})
    with pytest.raises(SystemExit) as failure:
        main(["lab-sql-validation", "--out-dir", str(root), "--authorized"])
    assert failure.value.code == 2
