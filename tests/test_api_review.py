"""Owned API declarations, never real endpoints, tokens or account actions."""
import copy
import hashlib
import json
import traceback
from pathlib import Path

import pytest

from hunterqa.api_review import MAX_BYTES, PROFILES, review_evidence, review_file
from hunterqa.cli import main


def evidence(key="api-security", value=None):
    return {"schema_version": 1, "records": [{"id": "owned-one", "skill": "offensive-" + key,
        "observations": dict.fromkeys(PROFILES[key], value)}]}


def spec(operation=None, **updates):
    return {"openapi": "3.1.1", "paths": {"/PRIVATE/{PRIVATE}": {"get": operation if operation is not None else {}}}, **updates}


def native(tmp_path, monkeypatch, data, mode="openapi-json"):
    path = tmp_path / "source.json"
    path.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return path, review_file(path, authorized=True, mode=mode)


def rules(report):
    return {f["rule_id"] for f in report["findings"]}


@pytest.mark.parametrize("key,field", [(k, f) for k, fs in PROFILES.items() for f in fs])
def test_both_contracts_positive_negative_and_unknown(key, field):
    data = evidence(key, True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field] = False
    report = review_evidence(data)
    assert [f["rule_id"] for f in report["findings"]] == ["api-review." + key + "." + field.replace("_", "-")]
    unknown = review_evidence(evidence(key))
    assert not unknown["findings"] and unknown["status"] == "insufficient-evidence"
    assert unknown["network_requests"] == unknown["external_tools_executed"] == unknown["referenced_files_opened"] == 0
    assert not any(unknown[k] for k in ("runtime_enforcement_verified", "authorization_verified", "business_logic_verified", "all_skills_automated"))
    assert unknown["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change", [
    lambda d: d.update(schema_version=True), lambda d: d.update(schema_version=2), lambda d: d.update(extra="PRIVATE"),
    lambda d: d.update(records=[]), lambda d: d["records"][0].update(id="PRIVATE BAD"), lambda d: d["records"][0].update(skill=[]),
    lambda d: d["records"][0].update(skill="offensive-unknown"), lambda d: d["records"][0].update(extra="PRIVATE"),
    lambda d: d["records"][0].update(observations={}), lambda d: d["records"][0]["observations"].update(authentication_reviewed=1),
    lambda d: d["records"][0]["observations"].update(authentication_reviewed="PRIVATE"),
    lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
])
def test_strict_evidence_schema(change):
    data = evidence()
    change(data)
    with pytest.raises(ValueError) as exc:
        review_evidence(data)
    assert "PRIVATE" not in str(exc.value)


def test_catalog_template_bounds_and_readiness(capsys):
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
    main(["api-review-catalog"])
    cat = json.loads(capsys.readouterr().out)
    assert len(cat["skills"]) == 2 and all(not r["active_api_testing_available"] for r in cat["skills"])
    root = Path(__file__).resolve().parents[1]
    report = review_evidence(json.loads((root / "templates/HunterQA-api-review-template.json").read_text()))
    assert len(report["records"]) == 2 and report["status"] == "insufficient-evidence"
    from hunterqa.coverage_audit import coverage_audit, render_checklist
    assert not coverage_audit()["all_seven_areas_complete"]
    assert next(p for p in coverage_audit()["category_packs"] if p["name"] == "API Security")["skills"] == cat["skills"]
    assert (root / "docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()


SCHEMES = {"PRIVATE": {"type": "http", "scheme": "bearer"}, "OTHER": {"type": "apiKey", "in": "header", "name": "PRIVATE"}}


@pytest.mark.parametrize("security,state,counts", [([], "no-requirement-declared", []), ([{}], "anonymous-alternative-declared", [0]),
    ([{}, {"PRIVATE": []}], "anonymous-alternative-declared", [0, 1]), ([{"PRIVATE": []}], "named-mechanisms-declared", [1]),
    ([{"PRIVATE": [], "OTHER": []}], "named-mechanisms-declared", [2]), ([{"PRIVATE": []}, {"OTHER": []}], "named-mechanisms-declared", [1, 1]),
    ([{"MISSING": []}], "unresolved-mechanism-declaration", [1])])
def test_security_or_and_anonymous_alternatives(tmp_path, monkeypatch, security, state, counts):
    _, report = native(tmp_path, monkeypatch, spec({"security": security}, components={"securitySchemes": SCHEMES}))
    row = report["records"][0]
    assert row["security"]["declaration"] == state and row["security"]["alternatives"] == counts
    assert row["security_source"] == "operation"
    assert ("api-review.openapi.optional-security" in rules(report)) == (state in ("no-requirement-declared", "anonymous-alternative-declared"))
    assert "PRIVATE" not in json.dumps(report) and "MISSING" not in json.dumps(report)


def test_operation_overrides_root_security_without_merging(tmp_path, monkeypatch):
    data = spec(components={"securitySchemes": SCHEMES}, security=[{"PRIVATE": []}])
    _, inherited = native(tmp_path, monkeypatch, data)
    assert inherited["records"][0]["security_source"] == "root"
    assert inherited["records"][0]["security"]["declaration"] == "named-mechanisms-declared"
    data["paths"]["/PRIVATE/{PRIVATE}"]["get"]["security"] = []
    _, overridden = native(tmp_path, monkeypatch, data)
    assert overridden["records"][0]["security"]["declaration"] == "no-requirement-declared"
    _, missing = native(tmp_path, monkeypatch, spec())
    assert missing["records"][0]["security"]["declaration"] == "not-declared" and not missing["findings"]


def test_security_reference_is_unresolved_and_paths_with_refs_are_skipped(tmp_path, monkeypatch):
    data = spec({"security": [{"PRIVATE": []}]}, components={"securitySchemes": {"PRIVATE": {"$ref": "https://PRIVATE/secret"}}})
    data["paths"]["/hidden"] = {"$ref": "./PRIVATE.json", "post": {"security": []}}
    _, report = native(tmp_path, monkeypatch, data)
    assert report["records"][0]["security"]["declaration"] == "unresolved-mechanism-declaration"
    assert report["source_review"]["referenced_paths_not_reviewed"] == 1
    assert report["source_review"]["inline_operations_skipped_with_referenced_paths"] == 1
    assert report["source_review"]["references_not_resolved"] == 2
    assert report["referenced_files_opened"] == 0 and "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("definition,key", [({"type": "apiKey", "in": "query", "name": "PRIVATE"}, "query-api-key"), ({"type": "http", "scheme": "Basic"}, "basic-auth")])
def test_definition_cues_do_not_assert_operation_usage(tmp_path, monkeypatch, definition, key):
    _, report = native(tmp_path, monkeypatch, spec(components={"securitySchemes": {"PRIVATE": definition}}))
    assert rules(report) == {"api-review.openapi." + key}
    assert report["findings"][0]["severity"] == "INFO"


def test_server_override_precedence_and_relative_urls(tmp_path, monkeypatch):
    data = spec(servers=[{"url": "http://PRIVATE"}])
    _, inherited = native(tmp_path, monkeypatch, data)
    assert "api-review.openapi.http-server" in rules(inherited)
    data["paths"]["/PRIVATE/{PRIVATE}"]["servers"] = [{"url": "/relative"}]
    _, path_override = native(tmp_path, monkeypatch, data)
    assert not path_override["findings"]
    data["paths"]["/PRIVATE/{PRIVATE}"]["get"]["servers"] = [{"url": "HTTP://{PRIVATE}/v1"}]
    _, op_override = native(tmp_path, monkeypatch, data)
    assert "api-review.openapi.http-server" in rules(op_override) and "PRIVATE" not in json.dumps(op_override)


def parameter(schema):
    return {"name": "limit", "in": "query", "schema": schema}


@pytest.mark.parametrize("version,schema,bound", [("3.0.4", {"type": "integer"}, False), ("3.0.4", {"type": "integer", "exclusiveMaximum": False}, False),
    ("3.0.4", {"type": "integer", "maximum": 50, "exclusiveMaximum": True}, True), ("3.1.1", {"type": "integer", "exclusiveMaximum": 50}, True),
    ("3.1.1", {"type": "number", "maximum": 0}, True)])
def test_selected_pagination_bounds_respect_version_types(tmp_path, monkeypatch, version, schema, bound):
    _, report = native(tmp_path, monkeypatch, spec({"parameters": [parameter(schema)]}, openapi=version))
    assert ("api-review.openapi.pagination-bound" in rules(report)) == (not bound)


def test_parameter_override_and_unknown_references_do_not_create_bound_cues(tmp_path, monkeypatch):
    data = spec({"parameters": [parameter({"type": "integer", "maximum": 10})]})
    item = data["paths"]["/PRIVATE/{PRIVATE}"]
    item["parameters"] = [parameter({"type": "integer"})]
    _, overridden = native(tmp_path, monkeypatch, data)
    assert not overridden["findings"]
    item["get"]["parameters"] = [{"$ref": "./PRIVATE"}]
    _, unresolved = native(tmp_path, monkeypatch, data)
    assert not unresolved["findings"] and unresolved["records"][0]["parameters_status"] == "partial-unresolved-references"


def body(schema):
    return {"content": {"application/json": {"schema": schema}}}


@pytest.mark.parametrize("schema,key", [({"type": "array"}, "array-bound"), ({"type": "object", "additionalProperties": True}, "open-object")])
def test_selected_request_schema_cues_and_negative_controls(tmp_path, monkeypatch, schema, key):
    _, report = native(tmp_path, monkeypatch, spec({"requestBody": body(schema)}))
    assert rules(report) == {"api-review.openapi." + key}
    quiet = {**schema, "maxItems": 100, "additionalProperties": False}
    _, baseline = native(tmp_path, monkeypatch, spec({"requestBody": body(quiet)}))
    assert not baseline["findings"]


@pytest.mark.parametrize("schema", [True, False, {"$ref": "./PRIVATE"}, {"$dynamicRef": "https://PRIVATE"}, {"allOf": [{"type": "array"}]}])
def test_unresolved_composed_or_boolean_schemas_are_not_evaluated(tmp_path, monkeypatch, schema):
    _, report = native(tmp_path, monkeypatch, spec({"requestBody": body(schema)}))
    assert not report["findings"]
    assert report["records"][0]["request_body_status"] != "selected-inline-schema-only"
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("change", [
    lambda d: d.update(openapi="3.2.1"), lambda d: d.update(openapi="2.0"), lambda d: d.update(paths=[]),
    lambda d: d.update(security=None), lambda d: d.update(servers=[{"url": None}]),
    lambda d: d["paths"]["/PRIVATE/{PRIVATE}"].update(get=[]),
    lambda d: d["paths"]["/PRIVATE/{PRIVATE}"]["get"].update(security=None),
    lambda d: d["paths"]["/PRIVATE/{PRIVATE}"]["get"].update(security=[{"PRIVATE": "PRIVATE"}]),
    lambda d: d["paths"]["/PRIVATE/{PRIVATE}"]["get"].update(parameters=[parameter({"type":"integer","maximum":None})]),
    lambda d: d["paths"]["/PRIVATE/{PRIVATE}"]["get"].update(parameters=[parameter({"type":"integer","exclusiveMaximum":False})]),
    lambda d: d["paths"]["/PRIVATE/{PRIVATE}"]["get"].update(parameters=[parameter({}),parameter({})]),
    lambda d: d["paths"]["/PRIVATE/{PRIVATE}"]["get"].update(requestBody=None),
    lambda d: d["paths"]["/PRIVATE/{PRIVATE}"]["get"].update(requestBody=body({"type":"array","maxItems":True})),
])
def test_selected_invalid_shapes_are_sanitized(tmp_path, monkeypatch, change):
    data = spec()
    change(data)
    with pytest.raises(ValueError) as exc:
        native(tmp_path, monkeypatch, data)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


def test_empty_or_referenced_only_description_is_insufficient(tmp_path, monkeypatch):
    for data in (spec(paths={}), spec(paths={"/PRIVATE": {"$ref": "./PRIVATE"}})):
        _, report = native(tmp_path, monkeypatch, data)
        assert report["status"] == "insufficient-evidence" and not report["records"]


def test_operation_limits_and_visible_findings_truncation(tmp_path, monkeypatch):
    methods = ("get", "post", "put", "patch", "delete")
    data = spec(paths={"/PRIVATE/" + str(i): {m: {"security": []} for m in methods} for i in range(100)}, servers=[{"url": "http://PRIVATE"}])
    _, report = native(tmp_path, monkeypatch, data)
    assert len(report["records"]) == 500 and len(report["findings"]) == 500
    assert report["truncated"] and report["candidates_not_retained"] == 500
    data["paths"]["/extra"] = {"get": {}}
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, data)
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, spec(paths={"/" + str(i): {} for i in range(201)}))


def test_depth_node_and_reference_bounds(tmp_path, monkeypatch):
    data = spec()
    nested = {}
    data["x-private"] = nested
    for _ in range(42):
        nested["child"] = {}
        nested = nested["child"]
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, data)
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, spec(**{"x-private": [0] * 20001}))
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, spec(**{"$ref": 1}))


@pytest.mark.parametrize("mode,data", [("normalized", evidence(value=False)), ("openapi-json", spec({"security": []}))])
def test_cli_authorization_private_nonoverwrite_scope_and_sarif(tmp_path, monkeypatch, mode, data):
    from hunterqa.sarif_export import export_sarif
    source, _ = native(tmp_path, monkeypatch, data, mode=mode)
    output = tmp_path / "report.json"
    args = ["api-review" if mode == "normalized" else "api-openapi-review", "--input", str(source), "--out", str(output)]
    with pytest.raises(PermissionError):
        main(args)
    assert not output.exists()
    main([*args, "--authorized"])
    report = json.loads(output.read_text())
    assert report["input_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert export_sarif(output)["runs"][0]["results"]
    before = output.read_bytes()
    with pytest.raises(FileExistsError):
        main([*args, "--authorized"])
    assert output.read_bytes() == before
    if __import__("os").name != "nt":
        assert output.stat().st_mode & 0o077 == 0
    approved = tmp_path / "approved"
    approved.mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(approved))
    with pytest.raises(ValueError, match="outside"):
        review_file(source, authorized=True, mode=mode)
    inside = approved / "source"
    inside.write_bytes(source.read_bytes())
    with pytest.raises(ValueError, match="outside"):
        main([args[0], "--input", str(inside), "--out", str(tmp_path / "forbidden"), "--authorized"])
    inside.write_bytes(b"x" * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        review_file(inside, authorized=True, mode=mode)


@pytest.mark.parametrize("raw", [b'{"PRIVATE":NaN}', b'{"PRIVATE":1,"PRIVATE":2}', b'\xffPRIVATE', b'{"PRIVATE":', b'{"PRIVATE":1e999}'])
def test_json_errors_hide_source_values(tmp_path, monkeypatch, raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path, monkeypatch, raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


def test_no_network_requests_or_reference_file_reads(tmp_path, monkeypatch):
    import socket
    import subprocess

    def deny(*args, **kwargs):
        pytest.fail("Unexpected external action")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(subprocess, "Popen", deny)
    data = spec({"requestBody": {"$ref": "file:///PRIVATE"}}, servers=[{"url": "http://PRIVATE"}])
    _, report = native(tmp_path, monkeypatch, data)
    assert report["network_requests"] == report["referenced_files_opened"] == 0
    assert report["records"][0]["request_body_status"] == "unresolved-reference"
    with pytest.raises(ValueError):
        review_file(tmp_path / "never-opened", authorized=True, mode="unknown")


@pytest.mark.parametrize("mode,data", [("normalized", evidence()), ("openapi-json", spec())])
def test_missing_roots_and_symlinks_rejected(tmp_path, monkeypatch, mode, data):
    source, _ = native(tmp_path, monkeypatch, data, mode=mode)
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS")
    with pytest.raises(ValueError):
        review_file(source, authorized=True, mode=mode)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    link = tmp_path / "link"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        review_file(link, authorized=True, mode=mode)


def test_receipts_distinguish_source_free_sarif_cases(tmp_path, monkeypatch):
    from hunterqa.sarif_export import export_sarif
    fingerprints = []
    for i in range(2):
        _, report = native(tmp_path, monkeypatch, spec({"security": [], "operationId": "PRIVATE-" + str(i)}))
        output = tmp_path / (str(i) + ".json")
        output.write_text(json.dumps(report))
        result = export_sarif(output)["runs"][0]["results"][0]
        fingerprints.append(result["partialFingerprints"])
        assert "PRIVATE" not in json.dumps(result)
    assert fingerprints[0] != fingerprints[1]


@pytest.mark.parametrize("change", [
    lambda d: d.update(security=[{}] * 21),
    lambda d: d.update(components={"securitySchemes": {str(i): {"type": "http", "scheme": "bearer"} for i in range(51)}}),
    lambda d: d.update(servers=[{"url": "/private"}] * 21),
    lambda d: d["paths"]["/PRIVATE/{PRIVATE}"]["get"].update(parameters=[parameter({})] * 101),
    lambda d: d["paths"]["/PRIVATE/{PRIVATE}"]["get"].update(requestBody={"content": {"private/" + str(i): {} for i in range(21)}}),
])
def test_selected_collection_bounds(tmp_path, monkeypatch, change):
    data = spec()
    change(data)
    with pytest.raises(ValueError):
        native(tmp_path, monkeypatch, data)
