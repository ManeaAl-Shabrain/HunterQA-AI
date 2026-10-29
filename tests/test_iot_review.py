"""Owned synthetic declarations and text files; no devices or target traffic."""
import copy
import hashlib
import json
import traceback

import pytest

from hunterqa.cli import main
from hunterqa.iot_review import AREAS, BUILD_FLAGS, MAX_BYTES, review_evidence, review_file


def evidence(area="hardware", value=None):
    return {"schema_version": 1, "records": [{"id": "owned-one", "area": area,
        "observations": dict.fromkeys(AREAS[area], value)}]}


def native(tmp_path, monkeypatch, mode, raw):
    path = tmp_path / "source.txt"
    path.write_bytes(raw.encode() if isinstance(raw, str) else raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return path, review_file(path, authorized=True, mode=mode)


@pytest.mark.parametrize("area,field", [(a, f) for a, fs in AREAS.items() for f in fs])
def test_each_normalized_observation_has_positive_negative_and_unknown_controls(area, field):
    quiet = evidence(area, True)
    baseline = review_evidence(quiet)
    assert not baseline["findings"] and baseline["status"] == "partial-offline-review"
    quiet["records"][0]["observations"][field] = False
    report = review_evidence(quiet)
    assert [f["rule_id"] for f in report["findings"]] == ["iot-review." + area + "." + field.replace("_", "-")]
    assert report["findings"][0]["verification_status"] == "unverified"
    unknown = review_evidence(evidence(area))
    assert not unknown["findings"] and unknown["status"] == "insufficient-evidence"
    assert unknown["network_requests"] == unknown["device_actions_executed"] == unknown["referenced_files_opened"] == unknown["external_tools_executed"] == 0
    assert not unknown["runtime_enforcement_verified"] and not unknown["signature_verified"]
    assert not unknown["all_skills_automated"] and unknown["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change", [
    lambda d: d.update(schema_version=True), lambda d: d.update(schema_version=2),
    lambda d: d.update(extra="PRIVATE"), lambda d: d.update(records=[]),
    lambda d: d["records"][0].update(id="PRIVATE BAD"), lambda d: d["records"][0].update(area=[]),
    lambda d: d["records"][0].update(area="unknown"), lambda d: d["records"][0].update(extra="PRIVATE"),
    lambda d: d["records"][0].update(observations={}),
    lambda d: d["records"][0]["observations"].update(debug_access_controlled=1),
    lambda d: d["records"][0]["observations"].update(debug_access_controlled="PRIVATE"),
    lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
])
def test_strict_schema_rejects_untrusted_shapes_without_contents(change):
    data = evidence()
    change(data)
    with pytest.raises(ValueError) as exc:
        review_evidence(data)
    assert "PRIVATE" not in str(exc.value)


def test_normalized_record_bounds():
    data = evidence()
    data["records"] = [{**data["records"][0], "id": "owned-" + str(i)} for i in range(11)]
    with pytest.raises(ValueError):
        review_evidence(data)
    data["records"] *= 9
    with pytest.raises(ValueError):
        review_evidence(data)


@pytest.mark.parametrize("topic,access,expected", [
    ("#", "readwrite", "root-wildcard"), ("devices/+/events", "write", "wildcard-write"),
    ("devices/#", "readwrite", "wildcard-write"), ("$SYS/broker/connection/+/state", "write", "system-write"),
])
def test_acl_selected_allow_cues_and_deny_controls(tmp_path, monkeypatch, topic, access, expected):
    _, report = native(tmp_path, monkeypatch, "mqtt-acl", "user PRIVATE-USER\ntopic " + access + " " + topic + "\n")
    assert "iot-review.mqtt-acl." + expected in {f["rule_id"] for f in report["findings"]}
    assert all(f["severity"] == "INFO" for f in report["findings"])
    assert "PRIVATE-USER" not in json.dumps(report) and topic not in json.dumps(report)
    _, denied = native(tmp_path, monkeypatch, "mqtt-acl", "user PRIVATE-USER\ntopic deny " + topic + "\n")
    assert not denied["findings"] and denied["status"] == "partial-offline-review"


def test_acl_contexts_global_patterns_and_literal_quiet_rules(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, "mqtt-acl", "# private comment\ntopic read public/events\nuser PRIVATE\ntopic read device/events\npattern write devices/%u/#\npattern read shared/#\n")
    keys = {f["rule_id"] for f in report["findings"]}
    assert keys == {"iot-review.mqtt-acl.before-user", "iot-review.mqtt-acl.wildcard-write", "iot-review.mqtt-acl.unbound-pattern"}
    rows = report["records"]
    assert [r["scope"] for r in rows] == ["before-user-section", "user-section", "pattern-global", "pattern-global"]
    assert report["findings"][0]["line_start"] == 2
    assert report["source_review"]["effective_permissions_computed"] is False
    assert not any(v in json.dumps(report) for v in ("PRIVATE", "public/events", "devices/%u"))


@pytest.mark.parametrize("raw", ["", "# comment\n", "user PRIVATE\n"])
def test_acl_without_rules_is_insufficient(tmp_path, monkeypatch, raw):
    _, report = native(tmp_path, monkeypatch, "mqtt-acl", raw)
    assert report["status"] == "insufficient-evidence" and not report["findings"]


@pytest.mark.parametrize("raw", [
    "include_dir PRIVATE", "plugin PRIVATE", "listener 1883", "topic", "user", " topic read #", " # comment",
    "topic read PRIVATE extra", "topic write private/#/bad", "topic read a+b", "topic read a#",
    "pattern read a/%u-suffix/#", "topic read private/%u/#", "topic write private\x00",
    "topic write \xff".encode("latin-1"), "topic read " + "a" * 1025,
])
def test_acl_rejects_unsupported_syntax_with_sanitized_tracebacks(tmp_path, monkeypatch, raw):
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, "mqtt-acl", raw)
    try:
        native(tmp_path, monkeypatch, "mqtt-acl", raw)
    except ValueError:
        assert "PRIVATE" not in traceback.format_exc()


def test_acl_rule_and_user_bounds(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, "mqtt-acl", "user PRIVATE\n" + "topic read #\n" * 400)
    assert len(report["records"]) == 400
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, "mqtt-acl", "topic read #\n" * 401)
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, "mqtt-acl", "user PRIVATE\n" * 129)


def test_acl_findings_truncation_is_visible(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, "mqtt-acl", "topic #\n" * 400)
    assert len(report["findings"]) == 500 and report["truncated"]
    assert report["candidates_not_retained"] == 300 and len(report["records"]) == 400


@pytest.mark.parametrize("key,bad", [("CONFIG_FIT_SIGNATURE", "n"), ("CONFIG_LEGACY_IMAGE_FORMAT", "y"), ("CONFIG_CMD_MEMORY", "y")])
def test_build_selected_flags_and_opposite_controls(tmp_path, monkeypatch, key, bad):
    _, report = native(tmp_path, monkeypatch, "uboot-config", key + "=" + bad + "\n")
    assert "iot-review.uboot." + key.lower().replace("_", "-") in {f["rule_id"] for f in report["findings"]}
    _, opposite = native(tmp_path, monkeypatch, "uboot-config", key + "=" + ("n" if bad == "y" else "y") + "\n")
    assert "iot-review.uboot." + key.lower().replace("_", "-") not in {f["rule_id"] for f in opposite["findings"]}
    assert opposite["status"] == "partial-offline-review"


def test_build_support_does_not_prove_verified_boot_or_read_secrets(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, "uboot-config", '# generated\nCONFIG_FIT=y\nCONFIG_FIT_SIGNATURE=y\n# CONFIG_CMD_MEMORY is not set\nCONFIG_PRIVATE_TOKEN="PRIVATE-SECRET"\n')
    assert len(report["findings"]) == 1
    assert report["findings"][0]["rule_id"] == "iot-review.uboot.verification-policy"
    assert report["findings"][0]["line_start"] == 3
    assert not report["signature_verified"] and not report["source_review"]["artifact_or_boot_chain_verified"]
    assert report["records"][0]["unknown_fields"] == ["CONFIG_LEGACY_IMAGE_FORMAT"]
    assert report["source_review"]["unselected_symbols_seen"] == 1
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("raw", ["", "# comments\n", 'CONFIG_PRIVATE="SECRET"\n'])
def test_missing_build_flags_stay_unknown(tmp_path, monkeypatch, raw):
    _, report = native(tmp_path, monkeypatch, "uboot-config", raw)
    assert report["status"] == "insufficient-evidence" and not report["findings"]
    assert report["records"][0]["unknown_fields"] == list(BUILD_FLAGS)


@pytest.mark.parametrize("raw", [
    "CONFIG_FIT_SIGNATURE=m", 'CONFIG_FIT_SIGNATURE="PRIVATE"', "CONFIG_FIT=y\nCONFIG_FIT=n", "CONFIG_FIT=y\n# CONFIG_FIT is not set",
    "source PRIVATE", "CONFIG_FIT =y", "export CONFIG_FIT=y", "CONFIG_FIT=y # PRIVATE", "CONFIG_FIT=", "CONFIG_FIT=y\x00",
])
def test_build_rejects_fragments_duplicates_and_invalid_selected_values(tmp_path, monkeypatch, raw):
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, "uboot-config", raw)


@pytest.mark.parametrize("mode,raw", [("normalized", json.dumps(evidence("mqtt", False))), ("mqtt-acl", "topic #\n"), ("uboot-config", "CONFIG_CMD_MEMORY=y\n")])
def test_cli_authorization_private_create_only_receipts_and_sarif(tmp_path, monkeypatch, capsys, mode, raw):
    from hunterqa.sarif_export import export_sarif
    path, _ = native(tmp_path, monkeypatch, mode, raw)
    output = tmp_path / "report.json"
    args = ["iot-review" if mode == "normalized" else "iot-config-review", "--input", str(path), "--out", str(output)]
    if mode != "normalized":
        args += ["--mode", mode]
    with pytest.raises(PermissionError):
        main(args)
    assert not output.exists()
    main([*args, "--authorized"])
    data = json.loads(output.read_text())
    assert data["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert export_sarif(output)["runs"][0]["results"]
    assert path.read_text() == raw
    before = output.read_bytes()
    with pytest.raises(FileExistsError):
        main([*args, "--authorized"])
    assert output.read_bytes() == before
    if __import__("os").name != "nt":
        assert output.stat().st_mode & 0o077 == 0
    assert capsys.readouterr().out == "Saved: " + str(output) + "\n"


@pytest.mark.parametrize("mode,raw", [("normalized", json.dumps(evidence())), ("mqtt-acl", "topic #"), ("uboot-config", "CONFIG_FIT=y")])
def test_scope_bounds_before_reads_and_outputs(tmp_path, monkeypatch, mode, raw):
    root = tmp_path / "approved"
    root.mkdir()
    outside = tmp_path / "private"
    outside.write_text(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    with pytest.raises(ValueError, match="outside"):
        review_file(outside, authorized=True, mode=mode)
    source = root / "source"
    source.write_text(raw)
    args = ["iot-review" if mode == "normalized" else "iot-config-review", "--input", str(source), "--out", str(tmp_path / "outside-report"), "--authorized"]
    if mode != "normalized":
        args += ["--mode", mode]
    with pytest.raises(ValueError, match="outside"):
        main(args)
    source.write_bytes(b"x" * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        review_file(source, authorized=True, mode=mode)


@pytest.mark.parametrize("mode", ("mqtt-acl", "uboot-config"))
def test_native_line_limits(tmp_path, monkeypatch, mode):
    for raw in ("#" + "a" * 4096, "#\n" * 20001):
        with pytest.raises(ValueError):
            native(tmp_path, monkeypatch, mode, raw)


@pytest.mark.parametrize("raw", [b'{"schema_version":1,"schema_version":1,"PRIVATE":0}', b'{"PRIVATE":NaN}', b'\xffPRIVATE', b'{"PRIVATE":'])
def test_json_errors_withhold_source_and_chained_values(tmp_path, monkeypatch, raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path, monkeypatch, "normalized", raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


def test_catalog_template_and_coverage_agree(tmp_path, monkeypatch, capsys):
    from pathlib import Path
    from hunterqa.coverage_audit import coverage_audit, render_checklist
    main(["iot-review-catalog"])
    cat = json.loads(capsys.readouterr().out)
    assert cat["skills"][0]["id"] == "offensive-iot" and not cat["all_skills_automated"]
    repo = Path(__file__).resolve().parents[1]
    template = json.loads((repo / "templates/HunterQA-iot-review-template.json").read_text())
    report = review_evidence(template)
    assert len(report["records"]) == 9 and report["status"] == "insufficient-evidence" and not report["findings"]
    audit = coverage_audit()
    assert not audit["all_seven_areas_complete"]
    assert next(p for p in audit["category_packs"] if p["name"] == "IoT & Embedded")["skills"] == cat["skills"]
    assert (repo / "docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()


def test_native_readers_do_not_use_network_or_processes(tmp_path, monkeypatch):
    import socket
    import subprocess

    def deny(*args, **kwargs):
        pytest.fail("Unexpected external action")

    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(subprocess, "Popen", deny)
    native(tmp_path, monkeypatch, "mqtt-acl", "user PRIVATE\npattern write device/%c/#\n")
    native(tmp_path, monkeypatch, "uboot-config", 'CONFIG_FIT_SIGNATURE=y\nCONFIG_PRIVATE="$(PRIVATE)"\n')
    with pytest.raises(ValueError):
        review_file(tmp_path / "not-opened", authorized=True, mode="unknown")


@pytest.mark.parametrize("mode,raw", [("normalized", json.dumps(evidence())), ("mqtt-acl", "topic #"), ("uboot-config", "CONFIG_FIT=y")])
def test_missing_scope_and_symlink_inputs_are_rejected(tmp_path, monkeypatch, mode, raw):
    source = tmp_path / "source"
    source.write_text(raw)
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS", raising=False)
    with pytest.raises(ValueError, match="HUNTERQA_APPROVED_ROOTS"):
        review_file(source, authorized=True, mode=mode)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    link = tmp_path / "link"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        review_file(link, authorized=True, mode=mode)


def test_native_case_receipts_keep_sarif_findings_distinct(tmp_path, monkeypatch):
    from hunterqa.sarif_export import export_sarif
    fingerprints = []
    for i in range(2):
        _, report = native(tmp_path, monkeypatch, "mqtt-acl", "user PRIVATE-" + str(i) + "\ntopic read #\n")
        output = tmp_path / (str(i) + ".json")
        output.write_text(json.dumps(report))
        finding = export_sarif(output)["runs"][0]["results"][0]
        fingerprints.append(finding["partialFingerprints"])
        assert "PRIVATE" not in json.dumps(finding)
    assert fingerprints[0] != fingerprints[1]


def test_maximum_normalized_records_and_nonmutation():
    data = {"schema_version": 1, "records": [
        {"id": area + "-" + str(i), "area": area, "observations": dict.fromkeys(fields, None)}
        for area, fields in AREAS.items() for i in range(10)]}
    before = copy.deepcopy(data)
    report = review_evidence(data)
    assert len(report["records"]) == 90 and report["status"] == "insufficient-evidence"
    assert before == data
