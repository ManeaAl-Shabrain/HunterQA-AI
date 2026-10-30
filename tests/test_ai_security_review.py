"""Owned saved cases and summary fixtures; no provider calls, agents or tool execution."""
import copy
import hashlib
import json
import socket
import subprocess
import traceback
from pathlib import Path

import pytest

from hunterqa.ai_security_review import CANARY, MAX_BYTES, PROFILES, review_evidence, review_file
from hunterqa.cli import main


def evidence(value=None):
    return {"schema_version":1,"records":[{"id":"owned-one","skill":"offensive-ai-security","observations":dict.fromkeys(PROFILES["ai-security"],value)}]}


def cases(*rows):
    return {"schema_version":1,"cases":list(rows)}


def canary(response=None):
    return {"id":"owned-canary","kind":"canary-disclosure","response":response}


def boundary(kind="tool-boundary",observed=None,allowed=None):
    a,o=("allowed_tools","observed_calls") if kind == "tool-boundary" else ("allowed_documents","retrieved_documents")
    return {"id":"owned-boundary","kind":kind,a:allowed if allowed is not None else ["public-id"],o:observed}


def evaluation(**fields):
    return json.dumps({"entry_type":"eval","probe":"PRIVATE","detector":"PRIVATE","passed":2,"total_evaluated":3,"fails":1,"nones":1,"total_processed":4,**fields})


def native(tmp_path,monkeypatch,data,mode="owned-cases-json"):
    path=tmp_path/"inventory"
    path.write_bytes(data if isinstance(data,bytes) else (data.encode() if isinstance(data,str) else json.dumps(data).encode()))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    return path,review_file(path,authorized=True,mode=mode)


def keys(report):
    return [f["rule_id"].removeprefix("ai-security-review.") for f in report["findings"]]


@pytest.mark.parametrize("field",PROFILES["ai-security"])
def test_contract_positive_negative_unknown(field):
    data=evidence(True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field]=False
    assert len(review_evidence(data)["findings"]) == 1
    report=review_evidence(evidence())
    assert report["status"] == "insufficient-evidence"
    assert report["network_requests"] == report["external_tools_executed"] == report["referenced_files_opened"] == 0
    assert not any(report[k] for k in ("runtime_authorization_verified","model_behavior_verified","model_robustness_verified","all_skills_automated"))
    assert report["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change",[lambda d:d.update(schema_version=True),lambda d:d.update(schema_version=2),
    lambda d:d.update(records=[]),lambda d:d.update(extra="PRIVATE"),lambda d:d["records"][0].update(id="PRIVATE BAD"),
    lambda d:d["records"][0].update(skill=[]),lambda d:d["records"][0].update(observations={}),
    lambda d:d["records"][0]["observations"].update(prompt_boundaries_reviewed=1),
    lambda d:d["records"].append(copy.deepcopy(d["records"][0]))])
def test_strict_contract(change):
    data=evidence()
    change(data)
    with pytest.raises(ValueError,match="withheld"):
        review_evidence(data)


@pytest.mark.parametrize("response,outcome,expected",[(None,"unobserved",[]),("","no-selected-violation",[]),
    ("PRIVATE normal response","no-selected-violation",[]),(CANARY,"violation",["canary-disclosure"]),
    ("PRIVATE "+CANARY+" PRIVATE","violation",["canary-disclosure"]),
    (CANARY.lower(),"no-selected-violation",[])])
def test_literal_canary_and_unknown_are_distinct(tmp_path,monkeypatch,response,outcome,expected):
    _,report=native(tmp_path,monkeypatch,cases(canary(response)))
    assert keys(report) == expected and report["records"][0]["outcome"] == outcome
    assert "PRIVATE" not in json.dumps(report) and CANARY not in json.dumps(report)
    assert report["source_review"]["unobserved_cases"] == int(response is None)


@pytest.mark.parametrize("kind",["tool-boundary","retrieval-boundary"])
@pytest.mark.parametrize("observed,expected,mismatches",[(None,"unobserved",None),([],"no-selected-violation",0),
    (["public-id"],"no-selected-violation",0),(["private-id"],"violation",1),(["private-id","private-id"],"violation",2)])
def test_saved_allowlists_are_only_constraints(tmp_path,monkeypatch,kind,observed,expected,mismatches):
    _,report=native(tmp_path,monkeypatch,cases(boundary(kind,observed)))
    row=report["records"][0]
    assert row["outcome"] == expected and row["mismatch_count"] == mismatches
    assert keys(report) == ([kind] if expected == "violation" else [])
    assert "private-id" not in json.dumps(report) and "public-id" not in json.dumps(report)


@pytest.mark.parametrize("data",[{},cases(),{"schema_version":True,"cases":[canary()]},
    cases({**canary(),"kind":"PRIVATE"}),cases({**canary(),"id":"PRIVATE BAD"}),cases(canary(),canary()),
    cases({**canary(),"extra":"PRIVATE"}),cases(canary(1)),cases(canary("x"*16385)),
    cases(boundary(observed=["PRIVATE BAD"])),cases(boundary(observed="PRIVATE")),
    cases(boundary(allowed=["public-id","public-id"])),cases(boundary(allowed=[str(i) for i in range(51)])),
    cases(boundary(observed=["public-id"]*201))])
def test_case_schema_and_budgets_withhold_values(tmp_path,monkeypatch,data):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,data)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("text,failed,total,profile",[
    (evaluation(),1,3,"evaluated-counts"),
    (evaluation(passed=3,fails=0),0,3,"evaluated-counts"),
    (evaluation(passed=0,fails=0,total_evaluated=0,total_processed=1),0,0,"evaluated-counts"),
    (json.dumps({"entry_type":"eval","passed":2,"total":3}),1,3,"legacy-total-counts"),
    (evaluation(total=3),1,3,"evaluated-counts"),
])
def test_selected_garak_numeric_profiles(tmp_path,monkeypatch,text,failed,total,profile):
    _,report=native(tmp_path,monkeypatch,text,"garak-jsonl")
    row=report["records"][0]
    assert row["declared_evaluated"] == total and row["derived_nonpassed"] == failed and row["count_profile"] == profile
    assert keys(report) == (["garak-nonpassed"] if failed else [])
    assert not row["outputs_independently_rescored"] and not report["source_review"]["model_score_computed"]
    assert "PRIVATE" not in json.dumps(report)
    if total == 0:
        assert report["status"] == "insufficient-evidence"


@pytest.mark.parametrize("fields",[{"passed":True},{"passed":-1},{"passed":4},{"total_evaluated":1.5},
    {"total_evaluated":1000001},{"total":4},{"fails":0},{"nones":True},{"total_processed":2},
    {"total_processed":5},{"probe":[]},{"detector":"x"*257}])
def test_garak_inconsistent_or_unsupported_counts(tmp_path,monkeypatch,fields):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,evaluation(**fields),"garak-jsonl")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_non_eval_rows_are_not_interpreted_or_imported(tmp_path,monkeypatch):
    data='\n'.join([json.dumps({"entry_type":"attempt","prompt":"PRIVATE","outputs":["PRIVATE"]}),
        json.dumps({"entry_type":"config","target_name":"PRIVATE"}),evaluation()])
    _,report=native(tmp_path,monkeypatch,data,"garak-jsonl")
    assert report["source_review"]["non_eval_rows_not_reviewed"] == 2 and len(report["records"]) == 1
    assert "PRIVATE" not in json.dumps(report) and not report["source_review"]["garak_installed_or_run"]


@pytest.mark.parametrize("raw",[b'{"cases":[],"cases":[]}',b'{"private":NaN}',b'{"ts":1e9999}',
    b'PRIVATE',b'\xff',b'['*45+b'0'+b']'*45,b' '*(MAX_BYTES+1)])
@pytest.mark.parametrize("mode",["owned-cases-json","garak-jsonl"])
def test_json_parser_bounds_and_privacy(tmp_path,monkeypatch,raw,mode):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,raw,mode)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_no_network_process_model_or_tool_execution(tmp_path,monkeypatch):
    def deny(*args,**kwargs):
        pytest.fail("Offline reviewer attempted process/network access")
    monkeypatch.setattr(socket,"socket",deny)
    monkeypatch.setattr(socket,"getaddrinfo",deny)
    monkeypatch.setattr(subprocess,"Popen",deny)
    data=cases(canary("PRIVATE "+CANARY),boundary(observed=["private-id"]))
    path,report=native(tmp_path,monkeypatch,data)
    original=path.read_bytes()
    assert report["input_sha256"] == hashlib.sha256(original).hexdigest() and path.read_bytes() == original
    assert "PRIVATE" not in json.dumps(report) and "private-id" not in json.dumps(report)
    _,report=native(tmp_path,monkeypatch,b'\xef\xbb\xbf'+evaluation().encode(),"garak-jsonl")
    assert keys(report) == ["garak-nonpassed"]


def test_cli_templates_catalog_coverage_sarif_and_nonoverwrite(tmp_path,monkeypatch,capsys):
    from hunterqa.coverage_audit import coverage_audit,render_checklist
    from hunterqa.sarif_export import export_sarif
    path=tmp_path/"evidence.json"
    path.write_bytes(Path("templates/HunterQA-ai-security-review-template.json").read_bytes())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    out=tmp_path/"report.json"
    main(["ai-security-review","--input",str(path),"--out",str(out),"--authorized"])
    assert json.loads(out.read_text())["status"] == "insufficient-evidence"
    with pytest.raises(FileExistsError):
        main(["ai-security-review","--input",str(path),"--out",str(out),"--authorized"])
    main(["ai-security-review-catalog"])
    assert "offensive-ai-security" in capsys.readouterr().out
    assert Path("docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()
    assert not coverage_audit()["all_seven_areas_complete"]
    assert any(p["name"] == "AI Security" for p in coverage_audit()["category_packs"])
    path.write_bytes(Path("templates/HunterQA-ai-owned-cases-template.json").read_bytes())
    out=tmp_path/"owned-report.json"
    main(["ai-security-evidence-review","--mode","owned-cases-json","--input",str(path),"--out",str(out),"--authorized"])
    assert json.loads(out.read_text())["source_review"]["unobserved_cases"] == 3
    path,_=native(tmp_path,monkeypatch,evaluation()+'\n'+evaluation(),"garak-jsonl")
    out=tmp_path/"garak-report.json"
    main(["ai-security-evidence-review","--mode","garak-jsonl","--input",str(path),"--out",str(out),"--authorized"])
    results=export_sarif(out)["runs"][0]["results"]
    assert len(results) == 2 and all("locations" not in r for r in results)
    assert results[0]["partialFingerprints"] != results[1]["partialFingerprints"]


def test_authorization_roots_symlinks_and_mode(tmp_path,monkeypatch):
    with pytest.raises(PermissionError):
        review_file(tmp_path/"absent")
    allowed=tmp_path/"allowed"
    allowed.mkdir()
    path,_=native(allowed,monkeypatch,cases(canary()))
    with pytest.raises(ValueError):
        main(["ai-security-evidence-review","--mode","owned-cases-json","--input",str(path),"--out",str(tmp_path/"outside.json"),"--authorized"])
    assert not (tmp_path/"outside.json").exists()
    link=allowed/"link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        review_file(link,authorized=True)
    with pytest.raises(ValueError):
        review_file(path,authorized=True,mode="live-model")
    other=tmp_path/"other"
    other.mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(other))
    with pytest.raises(ValueError):
        review_file(path,authorized=True)


def test_record_and_retention_bounds(tmp_path,monkeypatch):
    data=evidence()
    data["records"]=[{**data["records"][0],"id":"case-"+str(i)} for i in range(10)]
    assert len(review_evidence(data)["records"]) == 10
    data["records"].append({**data["records"][0],"id":"extra"})
    with pytest.raises(ValueError):
        review_evidence(data)
    with pytest.raises(ValueError):
        native(tmp_path,monkeypatch,cases(*[{**canary(),"id":"case-"+str(i)} for i in range(101)]))
    _,report=native(tmp_path,monkeypatch,'\n'.join([evaluation()]*1000),"garak-jsonl")
    assert len(report["records"]) == 1000 and len(report["findings"]) == 500
    assert report["truncated"] and report["candidates_not_retained"] == 500
    with pytest.raises(ValueError):
        native(tmp_path,monkeypatch,b'\n'*1001,"garak-jsonl")
    with pytest.raises(ValueError):
        native(tmp_path,monkeypatch,b'x'*16385,"garak-jsonl")
