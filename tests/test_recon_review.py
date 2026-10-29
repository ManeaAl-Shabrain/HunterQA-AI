"""Owned synthetic names and scope declarations; no DNS or OSINT collection."""
import copy
import hashlib
import json
import traceback
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.recon_review import MAX_BYTES, PROFILES, inventory_file, review_evidence, review_file, validate_scope


def evidence(key="osint", value=None):
    return {"schema_version": 1, "records": [{"id": "owned-one", "skill": "offensive-" + key,
        "observations": dict.fromkeys(PROFILES[key], value)}]}


def scope(subdomains=False, name="example.test"):
    return {"schema_version": 1, "domains": [{"name": name, "include_subdomains": subdomains}]}


def inventory(tmp_path, monkeypatch, raw, *, mode="names", rules=None, names=False):
    path, scoped = tmp_path / "source", tmp_path / "scope.json"
    path.write_bytes(raw.encode() if isinstance(raw, str) else raw)
    scoped.write_text(json.dumps(rules if rules is not None else scope(True)))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return path, scoped, inventory_file(path, scoped, authorized=True, mode=mode, include_names=names)


@pytest.mark.parametrize("key,field", [(k, f) for k, fs in PROFILES.items() for f in fs])
def test_both_contracts_have_positive_negative_and_unknown_controls(key, field):
    data = evidence(key, True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field] = False
    report = review_evidence(data)
    assert [f["rule_id"] for f in report["findings"]] == ["recon-review." + key + "." + field.replace("_", "-")]
    unknown = review_evidence(evidence(key))
    assert not unknown["findings"] and unknown["status"] == "insufficient-evidence"
    assert unknown["network_requests"] == unknown["dns_queries"] == unknown["external_tools_executed"] == unknown["referenced_files_opened"] == 0
    assert not unknown["asset_ownership_verified"] and not unknown["current_dns_verified"] and not unknown["all_skills_automated"]
    assert unknown["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change", [
    lambda d: d.update(schema_version=True), lambda d: d.update(schema_version=2), lambda d: d.update(extra="PRIVATE"),
    lambda d: d.update(records=[]), lambda d: d["records"][0].update(id="PRIVATE BAD"), lambda d: d["records"][0].update(skill=[]),
    lambda d: d["records"][0].update(skill="offensive-unknown"), lambda d: d["records"][0].update(extra="PRIVATE"),
    lambda d: d["records"][0].update(observations={}), lambda d: d["records"][0]["observations"].update(asset_attribution_reviewed=1),
    lambda d: d["records"][0]["observations"].update(asset_attribution_reviewed="PRIVATE"),
    lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
])
def test_evidence_schema_is_strict(change):
    data = evidence()
    change(data)
    with pytest.raises(ValueError) as exc:
        review_evidence(data)
    assert "PRIVATE" not in str(exc.value)


def test_contract_limits_templates_and_coverage(capsys):
    data = {"schema_version": 1, "records": [{"id": k + "-" + str(i), "skill": "offensive-" + k,
        "observations": dict.fromkeys(fs, None)} for k, fs in PROFILES.items() for i in range(10)]}
    before = copy.deepcopy(data)
    assert len(review_evidence(data)["records"]) == 20 and before == data
    data["records"].append({**data["records"][0], "id": "extra"})
    with pytest.raises(ValueError):
        review_evidence(data)
    data["records"] = [{**data["records"][0], "id": "row-" + str(i)} for i in range(11)]
    with pytest.raises(ValueError):
        review_evidence(data)
    main(["recon-review-catalog"])
    cat = json.loads(capsys.readouterr().out)
    assert len(cat["skills"]) == 2 and all(not r["live_collection_available"] for r in cat["skills"])
    root = Path(__file__).resolve().parents[1]
    report = review_evidence(json.loads((root / "templates/HunterQA-recon-review-template.json").read_text()))
    assert len(report["records"]) == 2 and report["status"] == "insufficient-evidence"
    assert validate_scope(json.loads((root / "templates/HunterQA-recon-scope-template.json").read_text())) == [("example.test", False)]
    from hunterqa.coverage_audit import coverage_audit, render_checklist
    audit = coverage_audit()
    assert not audit["all_seven_areas_complete"]
    assert next(p for p in audit["category_packs"] if p["name"] == "Reconnaissance")["skills"] == cat["skills"]
    assert (root / "docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()


@pytest.mark.parametrize("name,subdomains,admitted", [
    ("example.test", False, True), ("EXAMPLE.TEST.", False, True), ("a.example.test", False, False),
    ("a.example.test", True, True), ("deep.a.example.test", True, True), ("notexample.test", True, False),
    ("example.test.invalid", True, False), ("example.test.invalid.", True, False), ("*.example.test", False, False),
    ("*.example.test", True, True), ("*.a.example.test", True, True), ("*.outside.test", True, False),
])
def test_scope_boundaries_exact_and_wildcard_patterns(tmp_path, monkeypatch, name, subdomains, admitted):
    _, _, report = inventory(tmp_path, monkeypatch, name + "\n", rules=scope(subdomains), names=True)
    assert len(report["records"]) == int(admitted)
    assert report["inventory_counts"]["outside_scope"] == int(not admitted)
    assert not report["source_review"]["wildcards_expanded"] and not report["source_review"]["active_targets_enrolled"]


@pytest.mark.parametrize("name", ["https://example.test", "person@example.test", "example.test:443", "example.test/path", "127.0.0.1", "192.000.2.1", "[::1]", "localhost", "exämple.test", "a..example.test", "-a.example.test", "a-.example.test", "_service.example.test", "foo.*.example.test", "*.*.example.test", "example.test..", "a" * 64 + ".example.test", ".".join(["a" * 63] * 4)])
def test_invalid_candidates_are_counted_without_echoing_values(tmp_path, monkeypatch, name):
    _, _, report = inventory(tmp_path, monkeypatch, name + "\n")
    assert report["inventory_counts"]["invalid_names"] == 1 and not report["records"]
    assert report["status"] == "insufficient-evidence"
    assert name not in json.dumps(report)


def test_deduplication_private_output_and_source_reference_caps(tmp_path, monkeypatch):
    _, _, report = inventory(tmp_path, monkeypatch, "A.example.test.\n" + "a.example.test\n" * 11)
    assert len(report["records"]) == 1
    row = report["records"][0]
    assert row["canonical_name_sha256"] == hashlib.sha256(b"a.example.test").hexdigest()
    assert report["inventory_counts"]["duplicate_admitted_names"] == 11
    assert len(row["source_observations"]) == 10 and row["source_observations_not_retained"] == 2
    assert row["source_observations"][0] == {"source_row": 1, "name_index": 1}
    assert "a.example.test" not in json.dumps(report) and "name" not in row
    _, _, visible = inventory(tmp_path, monkeypatch, "a.example.test\noutside.test\n", names=True)
    assert visible["records"][0]["name"] == "a.example.test"
    assert "outside.test" not in json.dumps(visible)


def test_ct_name_value_only_no_certificate_or_current_dns_claim(tmp_path, monkeypatch):
    raw = json.dumps([{"name_value": "EXAMPLE.TEST\n*.example.test\na.example.test", "common_name": "PRIVATE", "issuer_name": "PRIVATE", "id": 123},
        {"name_value": "a.example.test\noutside.test\nperson@example.test"}])
    _, _, report = inventory(tmp_path, monkeypatch, raw, mode="ct-names-json")
    counts = report["inventory_counts"]
    assert counts == {"candidates_seen": 6, "invalid_names": 1, "outside_scope": 1, "duplicate_admitted_names": 1, "unique_admitted_names": 3, "wildcard_patterns": 1}
    assert {f["rule_id"] for f in report["findings"]} == {"recon-review.inventory.wildcard-patterns", "recon-review.inventory.ct-attribution"}
    assert not report["certificate_or_ct_proof_verified"] and not report["current_dns_verified"]
    assert not any(v in json.dumps(report) for v in ("PRIVATE", "outside.test", "example.test"))
    assert report["records"][2]["source_observations"] == [{"source_row": 1, "name_index": 3}, {"source_row": 2, "name_index": 1}]


def test_union_scope_is_explicit_and_broad_wildcard_cannot_match_narrow_scope(tmp_path, monkeypatch):
    rules = {"schema_version": 1, "domains": [{"name": "a.example.test", "include_subdomains": True}, {"name": "b.example.test", "include_subdomains": False}]}
    _, _, report = inventory(tmp_path, monkeypatch, "*.example.test\n*.a.example.test\nx.a.example.test\nx.b.example.test\nb.example.test\n", rules=rules)
    assert report["inventory_counts"]["unique_admitted_names"] == 3 and report["inventory_counts"]["outside_scope"] == 2


@pytest.mark.parametrize("data", [scope(name="*.example.test"), scope(name="https://example.test"), scope(name="example.test "), scope(name="127.0.0.1"),
    {"schema_version": True, "domains": []}, {"schema_version": 1, "domains": []}, {"schema_version": 1, "domains": [{"name": "example.test", "include_subdomains": 1}]},
    {"schema_version": 1, "domains": [{"name": "example.test", "include_subdomains": False}, {"name": "EXAMPLE.TEST.", "include_subdomains": True}]}])
def test_invalid_or_ambiguous_scopes_fail(data):
    with pytest.raises(ValueError):
        validate_scope(data)


@pytest.mark.parametrize("raw", ["{}", '[{"common_name":"PRIVATE"}]', '[{"name_value":1}]', '[{"name_value":"PRIVATE","name_value":"PRIVATE"}]', '[{"name_value":NaN}]'])
def test_bad_ct_shapes_fail_without_values(tmp_path, monkeypatch, raw):
    with pytest.raises(ValueError) as exc:
        inventory(tmp_path, monkeypatch, raw, mode="ct-names-json")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


def test_inventory_and_scope_size_bounds(tmp_path, monkeypatch):
    for raw, mode in (("\n" * 2001, "names"), ("a" * 1025, "names"), (json.dumps([{"name_value":"example.test"}] * 501), "ct-names-json"),
        (json.dumps([{"name_value":"example.test\n" * 101}]), "ct-names-json"), (json.dumps([{"name_value":"a" * 8193}]), "ct-names-json"),
        ("\n".join("n" + str(i) + ".example.test" for i in range(1001)), "names")):
        with pytest.raises(ValueError):
            inventory(tmp_path, monkeypatch, raw, mode=mode)
    with pytest.raises(ValueError):
        validate_scope({"schema_version": 1, "domains": [{"name": "n" + str(i) + ".example.test", "include_subdomains": False} for i in range(21)]})
    _, _, report = inventory(tmp_path, monkeypatch, "\n".join("n" + str(i) + ".example.test" for i in range(1000)))
    assert len(report["records"]) == 1000


@pytest.mark.parametrize("raw", [b"\xffPRIVATE", b"PRIVATE\0", b"\x1b[31mPRIVATE"])
def test_names_encoding_errors_withhold_contents(tmp_path, monkeypatch, raw):
    with pytest.raises(ValueError) as exc:
        inventory(tmp_path, monkeypatch, raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


@pytest.mark.parametrize("mode", ("names", "ct-names-json"))
def test_inventory_cli_private_receipts_nonoverwrite_and_sarif(tmp_path, monkeypatch, mode):
    from hunterqa.sarif_export import export_sarif
    raw = "*.example.test\n" if mode == "names" else json.dumps([{"name_value": "*.example.test"}])
    source, scoped, _ = inventory(tmp_path, monkeypatch, raw, mode=mode)
    output = tmp_path / "report.json"
    args = ["recon-inventory", "--input", str(source), "--scope", str(scoped), "--mode", mode, "--out", str(output)]
    with pytest.raises(PermissionError):
        main(args)
    assert not output.exists()
    main([*args, "--authorized"])
    report = json.loads(output.read_text())
    assert report["input_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert report["scope_sha256"] == hashlib.sha256(scoped.read_bytes()).hexdigest()
    assert export_sarif(output)["runs"][0]["results"] and "example.test" not in output.read_text()
    before = output.read_bytes()
    with pytest.raises(FileExistsError):
        main([*args, "--authorized"])
    assert output.read_bytes() == before
    if __import__("os").name != "nt":
        assert output.stat().st_mode & 0o077 == 0
    main([a if a != str(output) else str(tmp_path / "named.json") for a in args] + ["--authorized", "--include-names"])
    assert json.loads((tmp_path / "named.json").read_text())["records"][0]["name"] == "*.example.test"


def test_normalized_cli_authorization_and_private_output(tmp_path, monkeypatch):
    from hunterqa.sarif_export import export_sarif
    source = tmp_path / "source.json"
    source.write_text(json.dumps(evidence(value=False)))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    output = tmp_path / "report.json"
    args = ["recon-review", "--input", str(source), "--out", str(output)]
    with pytest.raises(PermissionError):
        main(args)
    main([*args, "--authorized"])
    assert export_sarif(output)["runs"][0]["results"]
    with pytest.raises(FileExistsError):
        main([*args, "--authorized"])


def test_both_inputs_and_output_require_approved_roots(tmp_path, monkeypatch):
    source, scoped, _ = inventory(tmp_path, monkeypatch, "example.test\n")
    approved = tmp_path / "approved"
    approved.mkdir()
    inside_source, inside_scope = approved / "names", approved / "scope"
    inside_source.write_bytes(source.read_bytes())
    inside_scope.write_bytes(scoped.read_bytes())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(approved))
    for first, second in ((source, inside_scope), (inside_source, scoped)):
        with pytest.raises(ValueError, match="outside"):
            inventory_file(first, second, authorized=True)
    with pytest.raises(ValueError, match="outside"):
        main(["recon-inventory", "--input", str(inside_source), "--scope", str(inside_scope), "--out", str(tmp_path / "forbidden"), "--authorized"])
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS")
    with pytest.raises(ValueError):
        review_file(inside_source, authorized=True)


@pytest.mark.parametrize("which", ("source", "scope"))
def test_read_size_and_symlink_limits_on_both_inputs(tmp_path, monkeypatch, which):
    source, scoped, _ = inventory(tmp_path, monkeypatch, "example.test\n")
    target = source if which == "source" else scoped
    original = target.read_bytes()
    target.write_bytes(b"x" * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        inventory_file(source, scoped, authorized=True)
    target.write_bytes(original)
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        inventory_file(link if which == "source" else source, link if which == "scope" else scoped, authorized=True)


def test_sarif_context_changes_with_scope_without_exporting_names(tmp_path, monkeypatch):
    from hunterqa.sarif_export import export_sarif
    fingerprints = []
    for i, rules in enumerate((scope(True), scope(True, "a.example.test"))):
        _, _, report = inventory(tmp_path, monkeypatch, "*.a.example.test\n", rules=rules)
        output = tmp_path / (str(i) + ".json")
        output.write_text(json.dumps(report))
        row = export_sarif(output)["runs"][0]["results"][0]
        fingerprints.append(row["partialFingerprints"])
        assert "example.test" not in json.dumps(row)
    assert fingerprints[0] != fingerprints[1]


def test_no_dns_network_external_tools_or_automatic_enrollment(tmp_path, monkeypatch):
    import socket
    import subprocess

    def deny(*args, **kwargs):
        pytest.fail("Unexpected external action")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(subprocess, "Popen", deny)
    _, _, report = inventory(tmp_path, monkeypatch, "example.test\noutside.test\n")
    assert report["network_requests"] == report["dns_queries"] == 0
    assert not report["source_review"]["active_targets_enrolled"]
    with pytest.raises(ValueError):
        inventory_file(tmp_path / "never-opened", tmp_path / "never-opened", authorized=True, mode="unknown")


@pytest.mark.parametrize("raw", [b'{"PRIVATE":NaN}', b'{"PRIVATE":1,"PRIVATE":2}', b'\xffPRIVATE', b'{"PRIVATE":'])
def test_normalized_json_errors_withhold_contents(tmp_path, monkeypatch, raw):
    source = tmp_path / "source"
    source.write_bytes(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError) as exc:
        review_file(source, authorized=True)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


def test_ct_total_candidate_bound_and_empty_capture(tmp_path, monkeypatch):
    raw = json.dumps([{"name_value": "example.test\n" * 100}] * 21)
    with pytest.raises(ValueError):
        inventory(tmp_path, monkeypatch, raw, mode="ct-names-json")
    _, _, report = inventory(tmp_path, monkeypatch, "[]", mode="ct-names-json")
    assert report["status"] == "insufficient-evidence" and report["inventory_counts"]["candidates_seen"] == 0


def test_selected_ascii_punycode_is_retained_without_idna_conversion(tmp_path, monkeypatch):
    _, _, report = inventory(tmp_path, monkeypatch, "XN--BCHER-KVA.example.test.\n", names=True)
    assert report["records"][0]["name"] == "xn--bcher-kva.example.test"
    assert not report["asset_ownership_verified"]


def test_name_export_flag_cannot_be_enabled_with_untyped_api_values(tmp_path):
    with pytest.raises(ValueError):
        inventory_file(tmp_path / "never-opened", tmp_path / "never-opened", authorized=True, include_names="true")
