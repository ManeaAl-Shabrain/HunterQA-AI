"""Owned synthetic evidence and PE headers, never executable payloads."""
import copy
import hashlib
import json
import struct
import traceback
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.infrastructure_review import FLAGS, MAX_BYTES, PROFILES, review_evidence, review_file


def evidence(key="initial-access", value=None):
    return {"schema_version": 1, "records": [{"id": "owned-one", "skill": "offensive-" + key,
        "observations": dict.fromkeys(PROFILES[key], value)}]}


def pe(machine=0x8664, flags=0x160, section_flags=0x60000000, directories=16):
    """Only synthetic scalar headers/zero data; no code, imports or payload."""
    raw = bytearray(1024)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 0x80)
    raw[0x80:0x84] = b"PE\0\0"
    opt_size = 224 if machine == 0x14C else 240
    struct.pack_into("<HH", raw, 0x84, machine, 1)
    struct.pack_into("<HH", raw, 0x94, opt_size, 0x2)
    struct.pack_into("<H", raw, 0x98, 0x10B if machine == 0x14C else 0x20B)
    struct.pack_into("<I", raw, 0x98 + 60, 512)
    struct.pack_into("<H", raw, 0x98 + 70, flags)
    struct.pack_into("<I", raw, 0x98 + (92 if machine == 0x14C else 108), directories)
    section = 0x98 + opt_size
    raw[section:section + 8] = b"PRIVATE!"
    struct.pack_into("<II", raw, section + 16, 512, 512)
    struct.pack_into("<I", raw, section + 36, section_flags)
    return bytes(raw)


def native(tmp_path, monkeypatch, mode, raw):
    path = tmp_path / "source"
    path.write_bytes(raw.encode() if isinstance(raw, str) else raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return path, review_file(path, authorized=True, mode=mode)


@pytest.mark.parametrize("key,field", [(k, f) for k, fs in PROFILES.items() for f in fs])
def test_all_seven_contracts_have_positive_negative_and_unknown_controls(key, field):
    data = evidence(key, True)
    quiet = review_evidence(data)
    assert not quiet["findings"] and quiet["status"] == "partial-offline-review"
    data["records"][0]["observations"][field] = False
    report = review_evidence(data)
    assert [f["rule_id"] for f in report["findings"]] == ["infrastructure-review." + key + "." + field.replace("_", "-")]
    assert report["findings"][0]["verification_status"] == "unverified"
    unknown = review_evidence(evidence(key))
    assert not unknown["findings"] and unknown["status"] == "insufficient-evidence"
    assert unknown["network_requests"] == unknown["external_tools_executed"] == unknown["binaries_loaded"] == unknown["referenced_files_opened"] == 0
    assert not unknown["runtime_enforcement_verified"] and not unknown["signature_verified"]
    assert not unknown["all_skills_automated"] and unknown["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change", [
    lambda d: d.update(schema_version=True), lambda d: d.update(schema_version=2), lambda d: d.update(extra="PRIVATE"),
    lambda d: d.update(records=[]), lambda d: d["records"][0].update(id="PRIVATE BAD"), lambda d: d["records"][0].update(skill=[]),
    lambda d: d["records"][0].update(skill="offensive-unknown"), lambda d: d["records"][0].update(extra="PRIVATE"),
    lambda d: d["records"][0].update(observations={}), lambda d: d["records"][0]["observations"].update(remote_access_mfa_required=1),
    lambda d: d["records"][0]["observations"].update(remote_access_mfa_required="PRIVATE"),
    lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
])
def test_evidence_shapes_and_values_are_strict(change):
    data = evidence()
    change(data)
    with pytest.raises(ValueError) as exc:
        review_evidence(data)
    assert "PRIVATE" not in str(exc.value)


def test_record_limits_template_and_nonmutation(capsys):
    data = {"schema_version": 1, "records": [{"id": k + "-" + str(i), "skill": "offensive-" + k,
        "observations": dict.fromkeys(fs, None)} for k, fs in PROFILES.items() for i in range(10)]}
    before = copy.deepcopy(data)
    assert len(review_evidence(data)["records"]) == 70 and before == data
    data["records"].append({**data["records"][0], "id": "extra"})
    with pytest.raises(ValueError):
        review_evidence(data)
    data["records"] = [{**data["records"][0], "id": "one-" + str(i)} for i in range(11)]
    with pytest.raises(ValueError):
        review_evidence(data)
    main(["infrastructure-review-catalog"])
    cat = json.loads(capsys.readouterr().out)
    assert len(cat["skills"]) == 7 and all(not r["evasion_execution_available"] for r in cat["skills"])
    root = Path(__file__).resolve().parents[1]
    template = json.loads((root / "templates/HunterQA-infrastructure-review-template.json").read_text())
    report = review_evidence(template)
    assert len(report["records"]) == 7 and report["status"] == "insufficient-evidence" and not report["findings"]
    from hunterqa.coverage_audit import coverage_audit, render_checklist
    audit = coverage_audit()
    assert not audit["all_seven_areas_complete"]
    assert next(p for p in audit["category_packs"] if p["name"] == "Infrastructure & Red Team")["skills"] == cat["skills"]
    assert (root / "docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()


@pytest.mark.parametrize("machine", (0x14C, 0x8664, 0xAA64))
def test_native_architectures_flags_and_privacy(tmp_path, monkeypatch, machine):
    _, report = native(tmp_path, monkeypatch, "pe-headers", pe(machine, 0xFFFF))
    row = report["records"][0]
    assert all(row["declared_header_flags"].values())
    assert row["format"] == ("PE32" if machine == 0x14C else "PE32+")
    assert not report["signature_verified"] and not report["runtime_enforcement_verified"]
    assert not report["source_review"]["complete_pe_validity_checked"]
    assert not report["source_review"]["cet_acg_cig_sehop_verified"]
    assert "PRIVATE" not in json.dumps(report)
    assert all(f["severity"] == "INFO" for f in report["findings"])


@pytest.mark.parametrize("flag,key", [("dynamic_base", "dynamic-base-absent"), ("nx_compatible", "nx-compatible-absent"), ("guard_cf", "guard-cf-absent")])
def test_missing_header_flags_are_cues_not_runtime_vulnerabilities(tmp_path, monkeypatch, flag, key):
    _, report = native(tmp_path, monkeypatch, "pe-headers", pe(0x14C, 0xFFFF & ~FLAGS[flag]))
    assert "infrastructure-review.pe." + key in {f["rule_id"] for f in report["findings"]}
    _, opposite = native(tmp_path, monkeypatch, "pe-headers", pe(0x14C, 0xFFFF))
    assert "infrastructure-review.pe." + key not in {f["rule_id"] for f in opposite["findings"]}


@pytest.mark.parametrize("machine", (0x14C, 0x8664, 0xAA64))
def test_dep_and_high_entropy_applicability(tmp_path, monkeypatch, machine):
    _, report = native(tmp_path, monkeypatch, "pe-headers", pe(machine, FLAGS["dynamic_base"]))
    keys = {f["rule_id"] for f in report["findings"]}
    assert ("infrastructure-review.pe.nx-compatible-absent" in keys) == (machine == 0x14C)
    assert ("infrastructure-review.pe.high-entropy-absent" in keys) == (machine != 0x14C)
    _, no_dynamic = native(tmp_path, monkeypatch, "pe-headers", pe(machine, 0))
    assert "infrastructure-review.pe.high-entropy-absent" not in {f["rule_id"] for f in no_dynamic["findings"]}


@pytest.mark.parametrize("permissions,expected", [(0xE0000000, True), (0xA0000000, True), (0x60000000, False), (0xC0000000, False), (0, False)])
def test_writable_executable_declarations(tmp_path, monkeypatch, permissions, expected):
    _, report = native(tmp_path, monkeypatch, "pe-headers", pe(section_flags=permissions))
    rows = [f for f in report["findings"] if f["rule_id"] == "infrastructure-review.pe.writable-executable-section"]
    assert bool(rows) == expected
    assert len(report["records"]) == (2 if expected else 1)


@pytest.mark.parametrize("offset,fmt,value", [
    (0x3C, "<I", 0), (0x3C, "<I", 0xFFFFFFFF), (0x84, "<H", 0), (0x86, "<H", 0), (0x86, "<H", 97),
    (0x94, "<H", 95), (0x94, "<H", 4097), (0x96, "<H", 0), (0x98, "<H", 0x10B),
    (0x98 + 108, "<I", 17), (0x98 + 60, "<I", 200), (0x98 + 60, "<I", 2048),
    (0x98 + 240 + 16, "<I", 1024), (0x98 + 240 + 20, "<I", 100),
])
def test_malformed_header_scalar_bounds_are_sanitized(tmp_path, monkeypatch, offset, fmt, value):
    raw = bytearray(pe())
    struct.pack_into(fmt, raw, offset, value)
    with pytest.raises(ValueError) as exc:
        native(tmp_path, monkeypatch, "pe-headers", bytes(raw))
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


@pytest.mark.parametrize("size", (0, 63, 128, 151, 200, 391, 430, 511, 1023))
def test_truncated_images_fail_without_native_parser_errors(tmp_path, monkeypatch, size):
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, "pe-headers", pe()[:size])


def test_no_sections_are_loaded_and_overlapping_raw_ranges_rejected(tmp_path, monkeypatch):
    raw = bytearray(pe())
    struct.pack_into("<H", raw, 0x86, 2)
    section = 0x98 + 240
    raw[section + 40:section + 80] = raw[section:section + 40]
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, "pe-headers", bytes(raw))
    struct.pack_into("<I", raw, section + 40 + 16, 0)
    _, report = native(tmp_path, monkeypatch, "pe-headers", bytes(raw))
    assert report["records"][0]["section_count"] == 2 and report["binaries_loaded"] == 0


@pytest.mark.parametrize("mode,raw", [("normalized", json.dumps(evidence(value=False)).encode()), ("pe-headers", pe())])
def test_authorization_scope_private_nonoverwrite_and_sarif(tmp_path, monkeypatch, mode, raw):
    from hunterqa.sarif_export import export_sarif
    path, _ = native(tmp_path, monkeypatch, mode, raw)
    output = tmp_path / "report.json"
    command = "infrastructure-review" if mode == "normalized" else "infrastructure-pe-review"
    args = [command, "--input", str(path), "--out", str(output)]
    with pytest.raises(PermissionError):
        main(args)
    assert not output.exists()
    main([*args, "--authorized"])
    data = json.loads(output.read_text())
    assert data["input_sha256"] == hashlib.sha256(raw).hexdigest() and path.read_bytes() == raw
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
    root = tmp_path / "private"
    root.mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    with pytest.raises(ValueError, match="outside"):
        review_file(path, authorized=True, mode=mode)
    inside = root / "source"
    inside.write_bytes(raw)
    with pytest.raises(ValueError, match="outside"):
        main([command, "--input", str(inside), "--out", str(tmp_path / "forbidden"), "--authorized"])
    inside.write_bytes(b"x" * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        review_file(inside, authorized=True, mode=mode)


@pytest.mark.parametrize("raw", [b'{"PRIVATE":NaN}', b'{"PRIVATE":1,"PRIVATE":2}', b'\xffPRIVATE', b'{"PRIVATE":'])
def test_invalid_json_withholds_values_and_exception_chaining(tmp_path, monkeypatch, raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path, monkeypatch, "normalized", raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


def test_no_network_process_or_binary_loading(tmp_path, monkeypatch):
    import ctypes
    import socket
    import subprocess

    def deny(*args, **kwargs):
        pytest.fail("Unexpected external action")

    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(subprocess, "Popen", deny)
    monkeypatch.setattr(ctypes, "CDLL", deny)
    native(tmp_path, monkeypatch, "pe-headers", pe())
    with pytest.raises(ValueError):
        review_file(tmp_path / "never-opened", authorized=True, mode="unknown")


@pytest.mark.parametrize("mode,raw", [("normalized", json.dumps(evidence()).encode()), ("pe-headers", pe())])
def test_symlink_input_rejected(tmp_path, monkeypatch, mode, raw):
    path, _ = native(tmp_path, monkeypatch, mode, raw)
    link = tmp_path / "link"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        review_file(link, authorized=True, mode=mode)


def test_native_receipts_distinguish_sarif_cases_without_section_names(tmp_path, monkeypatch):
    from hunterqa.sarif_export import export_sarif
    fingerprints = []
    for i in range(2):
        raw = bytearray(pe())
        raw[-1] = i
        _, report = native(tmp_path, monkeypatch, "pe-headers", bytes(raw))
        output = tmp_path / (str(i) + ".json")
        output.write_text(json.dumps(report))
        result = export_sarif(output)["runs"][0]["results"][0]
        fingerprints.append(result["partialFingerprints"])
        assert "PRIVATE" not in json.dumps(result)
    assert fingerprints[0] != fingerprints[1]


@pytest.mark.parametrize("machine", (0x14C, 0x8664, 0xAA64))
def test_zero_data_directories_and_uninitialized_section_are_allowed(tmp_path, monkeypatch, machine):
    raw = bytearray(pe(machine, directories=0))
    section = 0x98 + (224 if machine == 0x14C else 240)
    struct.pack_into("<I", raw, section + 16, 0)
    struct.pack_into("<I", raw, section + 20, 0)
    _, report = native(tmp_path, monkeypatch, "pe-headers", bytes(raw))
    assert report["status"] == "partial-offline-review"


@pytest.mark.parametrize("offset,replacement", [(0, b"ZZ"), (0x80, b"XX\0\0")])
def test_invalid_signatures_are_rejected(tmp_path, monkeypatch, offset, replacement):
    raw = bytearray(pe())
    raw[offset:offset + len(replacement)] = replacement
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, "pe-headers", bytes(raw))
