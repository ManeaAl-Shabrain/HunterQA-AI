"""Owned synthetic metrics and observations; no fuzz target or network execution."""
import copy
import hashlib
import json
import traceback
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.fuzzing_review import INT_FIELDS, MAX_BYTES, PROFILES, review_evidence, review_file


def evidence(key="fuzzing", value=None):
    return {"schema_version": 1, "records": [{"id": "owned-one", "skill": "offensive-" + key,
        "observations": dict.fromkeys(PROFILES[key], value)}]}


def native(tmp_path, monkeypatch, mode, raw):
    path = tmp_path / "source"
    path.write_bytes(raw.encode() if isinstance(raw, str) else raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return path, review_file(path, authorized=True, mode=mode)


@pytest.mark.parametrize("key,field", [(k, f) for k, fs in PROFILES.items() for f in fs])
def test_all_four_contracts_positive_negative_and_unknown(key, field):
    data = evidence(key, True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field] = False
    report = review_evidence(data)
    assert [f["rule_id"] for f in report["findings"]] == ["fuzzing-review." + key + "." + field.replace("_", "-")]
    unknown = review_evidence(evidence(key))
    assert not unknown["findings"] and unknown["status"] == "insufficient-evidence"
    assert unknown["network_requests"] == unknown["external_tools_executed"] == unknown["binaries_loaded"] == unknown["referenced_files_opened"] == 0
    assert not any(unknown[k] for k in ("fuzzer_executed", "coverage_verified", "reproduced", "exploitability_verified", "zero_day_confirmed", "all_skills_automated"))
    assert unknown["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change", [
    lambda d: d.update(schema_version=True), lambda d: d.update(schema_version=2), lambda d: d.update(extra="PRIVATE"),
    lambda d: d.update(records=[]), lambda d: d["records"][0].update(id="PRIVATE BAD"), lambda d: d["records"][0].update(skill=[]),
    lambda d: d["records"][0].update(skill="offensive-unknown"), lambda d: d["records"][0].update(extra="PRIVATE"),
    lambda d: d["records"][0].update(observations={}), lambda d: d["records"][0]["observations"].update(harness_reviewed=1),
    lambda d: d["records"][0]["observations"].update(harness_reviewed="PRIVATE"),
    lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
])
def test_strict_schema(change):
    data = evidence()
    change(data)
    with pytest.raises(ValueError) as exc:
        review_evidence(data)
    assert "PRIVATE" not in str(exc.value)


def test_limits_template_catalog_and_coverage(capsys):
    data = {"schema_version": 1, "records": [{"id": k + "-" + str(i), "skill": "offensive-" + k,
        "observations": dict.fromkeys(fs, None)} for k, fs in PROFILES.items() for i in range(10)]}
    before = copy.deepcopy(data)
    assert len(review_evidence(data)["records"]) == 40 and before == data
    data["records"].append({**data["records"][0], "id": "extra"})
    with pytest.raises(ValueError):
        review_evidence(data)
    data["records"] = [{**data["records"][0], "id": "row-" + str(i)} for i in range(11)]
    with pytest.raises(ValueError):
        review_evidence(data)
    main(["fuzzing-review-catalog"])
    cat = json.loads(capsys.readouterr().out)
    assert len(cat["skills"]) == 4 and all(not r["fuzzer_execution_available"] for r in cat["skills"])
    root = Path(__file__).resolve().parents[1]
    template = json.loads((root / "templates/HunterQA-fuzzing-review-template.json").read_text())
    report = review_evidence(template)
    assert len(report["records"]) == 4 and report["status"] == "insufficient-evidence" and not report["findings"]
    from hunterqa.coverage_audit import coverage_audit, render_checklist
    audit = coverage_audit()
    assert not audit["all_seven_areas_complete"]
    assert next(p for p in audit["category_packs"] if p["name"] == "Fuzzing & Vulnerability Research")["skills"] == cat["skills"]
    assert (root / "docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()


@pytest.mark.parametrize("key,bad,quiet", [("execs_done", "0", "100"), ("saved_crashes", "2", "0"), ("saved_hangs", "1", "0"), ("total_tmout", "5", "0"), ("stability", "98.50%", "100.00%")])
def test_afl_review_cues_and_negative_controls(tmp_path, monkeypatch, key, bad, quiet):
    _, report = native(tmp_path, monkeypatch, "afl-stats", key + " : " + bad + "\n")
    assert [f["rule_id"] for f in report["findings"]] == ["fuzzing-review.afl." + key.replace("_", "-")]
    assert report["findings"][0]["severity"] == "INFO" and report["findings"][0]["verification_status"] == "unverified"
    _, baseline = native(tmp_path, monkeypatch, "afl-stats", key + ": " + quiet + "\n")
    assert not baseline["findings"]


@pytest.mark.parametrize("key", INT_FIELDS)
def test_afl_integer_fields_are_explicit_and_bounded(tmp_path, monkeypatch, key):
    _, report = native(tmp_path, monkeypatch, "afl-stats", key + ": 123\n")
    assert report["records"][0]["declared_metrics"][key] == 123
    assert key not in report["records"][0]["unknown_fields"]


def test_afl_unselected_private_fields_and_bitmap_are_not_coverage(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, "afl-stats", "execs_done: 100\nexecs_per_sec: 12.50\nbitmap_cvg: 67.80%\ncommand_line: PRIVATE --token PRIVATE:/secret\nafl_banner: PRIVATE\n")
    metrics = report["records"][0]["declared_metrics"]
    assert metrics == {"execs_done": 100, "execs_per_sec": 12.5, "bitmap_cvg": 67.8}
    assert "PRIVATE" not in json.dumps(report) and not report["source_review"]["bitmap_metric_is_source_coverage"]
    assert report["source_review"]["unselected_fields_seen"] == 2 and not report["findings"]


@pytest.mark.parametrize("raw", ["", "command_line: PRIVATE\n", "unique_crashes: 0\npaths_total: 5\n"])
def test_afl_missing_or_legacy_unselected_metrics_are_unknown(tmp_path, monkeypatch, raw):
    _, report = native(tmp_path, monkeypatch, "afl-stats", raw)
    assert report["status"] == "insufficient-evidence" and not report["findings"]


@pytest.mark.parametrize("raw", ["execs_done: -1", "execs_done: 1.5", "execs_done: " + "9" * 19, "execs_per_sec: NaN", "execs_per_sec: 1e9", "stability: 101%", "bitmap_cvg: 12", "stability: -1%", "execs_done: 1\nexecs_done: 2", "command_line: PRIVATE\ncommand_line: PRIVATE", "bad PRIVATE", "bad key: PRIVATE", "execs_done: "])
def test_invalid_afl_values_and_duplicates_fail_sanitized(tmp_path, monkeypatch, raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path, monkeypatch, "afl-stats", raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


@pytest.mark.parametrize("event", ("READ", "INITED", "NEW", "REDUCE", "RELOAD", "pulse", "DONE"))
def test_libfuzzer_progress_types_and_redaction(tmp_path, monkeypatch, event):
    _, report = native(tmp_path, monkeypatch, "libfuzzer-log", "#144 " + event + " cov: 3 ft: 4 corp: 2/PRIVATE exec/s: 9 rss: PRIVATE MS: 1 PRIVATE\n")
    row = report["records"][0]
    assert row["event"] == event and row["declared_iterations"] == 144
    assert row["declared_metrics"] == {"cov": 3, "ft": 4, "corp": 2, "exec/s": 9}
    assert report["source_review"]["done_marker_seen"] == (event == "DONE")
    assert "PRIVATE" not in json.dumps(report)
    assert not report["source_review"]["source_coverage_percentage_computed"]


def test_libfuzzer_restart_interleaving_and_partial_capture(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, "libfuzzer-log", "#20 NEW cov: 3\n#2 INITED cov: 2\n")
    assert {f["rule_id"] for f in report["findings"]} == {"fuzzing-review.libfuzzer.counter-decrease", "fuzzing-review.libfuzzer.no-done-marker"}
    assert report["source_review"]["single_run_consistency"] == "not-established"
    assert not report["source_review"]["progress_deltas_computed"]
    _, quiet = native(tmp_path, monkeypatch, "libfuzzer-log", "#2 INITED cov: 2\n#20 DONE cov: 3\n")
    assert not quiet["findings"] and not quiet["coverage_verified"]


@pytest.mark.parametrize("diagnostic", ("deadly signal", "timeout", "out-of-memory"))
def test_libfuzzer_errors_are_unverified_markers(tmp_path, monkeypatch, diagnostic):
    _, report = native(tmp_path, monkeypatch, "libfuzzer-log", "==123== ERROR: libFuzzer: " + diagnostic + " PRIVATE 0xDEADBEEF\n#4 DONE cov: 1\n")
    assert len(report["findings"]) == 1 and report["records"][0]["diagnostic"] == diagnostic
    assert not report["reproduced"] and not report["source_review"]["unique_crashes_computed"]
    assert "PRIVATE" not in json.dumps(report) and "0xDEADBEEF" not in json.dumps(report)


@pytest.mark.parametrize("raw", ["", "INFO: PRIVATE\n", "#3 PRIVATE cov: 2\n", "embedded #4 DONE cov: 3\n", "SUMMARY: libFuzzer: deadly signal\n", "#4 DONE\n"])
def test_libfuzzer_missing_unsupported_or_incomplete_rows_are_insufficient(tmp_path, monkeypatch, raw):
    _, report = native(tmp_path, monkeypatch, "libfuzzer-log", raw)
    assert report["status"] == "insufficient-evidence" and not report["findings"]
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("tail", ("cov: -1", "ft: 1e3", "corp: 2", "corp: 2/", "exec/s: NaN", "cov: 1 cov: 2", "cov: " + "1" * 19))
def test_invalid_selected_libfuzzer_values_fail(tmp_path, monkeypatch, tail):
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, "libfuzzer-log", "#1 DONE " + tail)


@pytest.mark.parametrize("mode", ("afl-stats", "libfuzzer-log"))
@pytest.mark.parametrize("raw", (b"\xffPRIVATE", b"PRIVATE\0", b"\x1b[31mPRIVATE", b"a" * 8193, b"\n" * 20001))
def test_native_line_and_encoding_limits(tmp_path, monkeypatch, mode, raw):
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, mode, raw)


def test_native_record_limits(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, "afl-stats", "\n".join("unknown_" + str(i) + ": PRIVATE" for i in range(512)))
    assert report["source_review"]["unselected_fields_seen"] == 512
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, "afl-stats", "\n".join("unknown_" + str(i) + ": PRIVATE" for i in range(513)))
    _, report = native(tmp_path, monkeypatch, "libfuzzer-log", "#1 DONE cov: 1\n" * 200)
    assert len(report["records"]) == 200
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, "libfuzzer-log", "#1 DONE cov: 1\n" * 201)


INPUTS = [("normalized", json.dumps(evidence(value=False)).encode()), ("afl-stats", b"saved_crashes: 1\n"), ("libfuzzer-log", b"ERROR: libFuzzer: timeout\n")]


@pytest.mark.parametrize("mode,raw", INPUTS)
def test_cli_authorization_roots_private_nonoverwrite_and_sarif(tmp_path, monkeypatch, mode, raw):
    from hunterqa.sarif_export import export_sarif
    path, _ = native(tmp_path, monkeypatch, mode, raw)
    output = tmp_path / "report.json"
    args = ["fuzzing-review" if mode == "normalized" else "fuzzing-artifact-review", "--input", str(path), "--out", str(output)]
    if mode != "normalized":
        args += ["--mode", mode]
    with pytest.raises(PermissionError):
        main(args)
    assert not output.exists()
    main([*args, "--authorized"])
    report = json.loads(output.read_text())
    assert report["input_sha256"] == hashlib.sha256(raw).hexdigest() and path.read_bytes() == raw
    assert export_sarif(output)["runs"][0]["results"]
    before = output.read_bytes()
    with pytest.raises(FileExistsError):
        main([*args, "--authorized"])
    assert output.read_bytes() == before
    if __import__("os").name != "nt":
        assert output.stat().st_mode & 0o077 == 0
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS")
    with pytest.raises(ValueError):
        review_file(path, authorized=True, mode=mode)
    root = tmp_path / "approved"
    root.mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    with pytest.raises(ValueError, match="outside"):
        review_file(path, authorized=True, mode=mode)
    inside = root / "source"
    inside.write_bytes(raw)
    scoped = [str(inside) if a == str(path) else a for a in args]
    with pytest.raises(ValueError, match="outside"):
        main([*scoped, "--authorized"])
    inside.write_bytes(b"x" * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        review_file(inside, authorized=True, mode=mode)


@pytest.mark.parametrize("raw", [b'{"PRIVATE":NaN}', b'{"PRIVATE":1,"PRIVATE":2}', b'\xffPRIVATE', b'{"PRIVATE":'])
def test_json_errors_withhold_contents(tmp_path, monkeypatch, raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path, monkeypatch, "normalized", raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


@pytest.mark.parametrize("mode,raw", INPUTS)
def test_symlink_input_rejected(tmp_path, monkeypatch, mode, raw):
    path, _ = native(tmp_path, monkeypatch, mode, raw)
    link = tmp_path / "link"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        review_file(link, authorized=True, mode=mode)


def test_no_execution_or_network(tmp_path, monkeypatch):
    import ctypes
    import socket
    import subprocess

    def deny(*args, **kwargs):
        pytest.fail("Unexpected external action")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(subprocess, "Popen", deny)
    monkeypatch.setattr(ctypes, "CDLL", deny)
    native(tmp_path, monkeypatch, "afl-stats", "command_line: PRIVATE\nsaved_crashes: 1\n")
    native(tmp_path, monkeypatch, "libfuzzer-log", "#4 DONE cov: 3\n")
    with pytest.raises(ValueError):
        review_file(tmp_path / "never-opened", authorized=True, mode="unknown")


@pytest.mark.parametrize("mode,first,second", [
    ("afl-stats", "command_line: PRIVATE-ONE\nsaved_crashes: 1\n", "command_line: PRIVATE-TWO\nsaved_crashes: 1\n"),
    ("libfuzzer-log", "ERROR: libFuzzer: timeout PRIVATE-ONE\n", "ERROR: libFuzzer: timeout PRIVATE-TWO\n"),
])
def test_receipts_distinguish_source_free_sarif_cases(tmp_path, monkeypatch, mode, first, second):
    from hunterqa.sarif_export import export_sarif
    fingerprints = []
    for i, source in enumerate((first, second)):
        _, report = native(tmp_path, monkeypatch, mode, source)
        output = tmp_path / (str(i) + ".json")
        output.write_text(json.dumps(report))
        finding = export_sarif(output)["runs"][0]["results"][0]
        fingerprints.append(finding["partialFingerprints"])
        assert "PRIVATE" not in json.dumps(finding)
    assert fingerprints[0] != fingerprints[1]
