"""Owned report fixtures and FIRST reference arithmetic; never validate targets or open evidence."""
import copy
import hashlib
import itertools
import json
import socket
import subprocess
import traceback
from decimal import localcontext
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.utility_review import MAX_BYTES, PROFILES, cvss31, render_markdown, review_evidence, review_file

VECTOR="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def evidence(key="fast-checking",value=None):
    return {"schema_version":1,"records":[{"id":"owned-one","skill":"offensive-"+key,"observations":dict.fromkeys(PROFILES[key],value)}]}


def finding(**changes):
    return {"rule_id":"PRIVATE","title":"PRIVATE","severity":"INFO","verification_status":"unverified",
        "remediation":"PRIVATE","evidence":[{"uri":"https://PRIVATE.invalid","sha256":"PRIVATE"}],
        "file_path":"PRIVATE.py","line_start":1,**changes}


def native(tmp_path,monkeypatch,data):
    path=tmp_path/"inventory.json"
    path.write_bytes(data if isinstance(data,bytes) else json.dumps(data).encode())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    return path,review_file(path,authorized=True,mode="finding-report-json")


def keys(report):
    return [f["rule_id"].removeprefix("utility-review.") for f in report["findings"]]


@pytest.mark.parametrize("key,field",[(k,f) for k,fs in PROFILES.items() for f in fs])
def test_contract_positive_negative_unknown(key,field):
    data=evidence(key,True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field]=False
    assert len(review_evidence(data)["findings"]) == 1
    report=review_evidence(evidence(key))
    assert report["status"] == "insufficient-evidence"
    assert report["network_requests"] == report["external_tools_executed"] == report["referenced_files_opened"] == 0
    assert not any(report[k] for k in ("evidence_contents_verified","analyst_verdicts_verified","metric_justification_verified","all_skills_automated"))
    assert report["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change",[lambda d:d.update(schema_version=True),lambda d:d.update(schema_version=2),
    lambda d:d.update(records=[]),lambda d:d.update(extra="PRIVATE"),lambda d:d["records"][0].update(id="PRIVATE BAD"),
    lambda d:d["records"][0].update(skill=[]),lambda d:d["records"][0].update(observations={}),
    lambda d:d["records"][0]["observations"].update(scope_and_budget_reviewed=1),
    lambda d:d["records"].append(copy.deepcopy(d["records"][0]))])
def test_strict_contract(change):
    data=evidence()
    change(data)
    with pytest.raises(ValueError,match="withheld"):
        review_evidence(data)


# Metric combinations/scores from FIRST v3.1 examples sections 3-10, plus boundaries.
@pytest.mark.parametrize("vector,score,level",[
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",6.4,"MEDIUM"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",3.1,"LOW"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",9.9,"CRITICAL"),
    ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L",4.2,"MEDIUM"),
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",7.2,"HIGH"),
    ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",7.8,"HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",7.5,"HIGH"),
    (VECTOR,9.8,"CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",10.0,"CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N",0.0,"NONE"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",0.0,"NONE"),
])
def test_reference_base_vectors(vector,score,level):
    with localcontext() as ctx:
        ctx.prec=6
        result=cvss31(vector)
        assert ctx.prec == 6
    assert result["base_score"] == score and result["base_severity"] == level
    assert result["vector"] == vector and not result["metric_justification_verified"]
    assert "FIRST" in result["attribution"]


@pytest.mark.parametrize("vector",[None,True,"PRIVATE",VECTOR.replace("3.1","4.0"),VECTOR.replace("3.1","3.0"),
    VECTOR+"/E:X",VECTOR.replace("AV:N","AV:X"),VECTOR.replace("/AC:L",""),VECTOR.replace("AC:L","AV:N"),
    VECTOR+"PRIVATE",VECTOR.replace("A:H","A:PRIVATE")])
def test_unsupported_vectors_rejected_without_echo(vector):
    with pytest.raises(ValueError) as exc:
        cvss31(vector)
    assert "PRIVATE" not in str(exc.value)


def test_all_base_combinations_bounded_and_canonical_order():
    for values in itertools.product("NALP","LH","NLH","NR","UC","NLH","NLH","NLH"):
        vector="CVSS:3.1/"+"/".join(k+":"+v for k,v in zip(("AV","AC","PR","UI","S","C","I","A"),values))
        result=cvss31(vector)
        assert 0 <= result["base_score"] <= 10
        assert round(result["base_score"]*10) == result["base_score"]*10
        if values[-3:] == ("N","N","N"):
            assert result["base_score"] == 0
    reverse="CVSS:3.1/"+"/".join(reversed(VECTOR.split("/")[1:]))
    assert cvss31(reverse) == cvss31(VECTOR)


@pytest.mark.parametrize("changes,expected",[
    ({"title":""},["missing-metadata"]),({"remediation":None},["missing-metadata"]),
    ({"evidence":[]},["evidence-metadata-missing"]),({"evidence":{}},["evidence-metadata-missing"]),
    ({"verification_status":"PRIVATE"},["verification-unknown"]),({"severity":"PRIVATE"},["severity-unknown"]),
    ({"verification_status":"confirmed"},[]),
    ({"cvss_score":9.8},["score-without-vector"]),
    ({"cvss_vector":VECTOR,"cvss_score":8.0,"cvss_justification":"PRIVATE"},["cvss-score-mismatch"]),
    ({"cvss_vector":VECTOR,"cvss_score":9.8,"severity":"LOW","cvss_justification":"PRIVATE"},["cvss-label-mismatch"]),
    ({"cvss_vector":VECTOR,"cvss_score":9.8,"severity":"CRITICAL","cvss_justification":"PRIVATE"},[]),
    ({"cvss_vector":VECTOR,"cvss_justification":" "},["cvss-justification-missing"]),
    ({"cvss_vector":VECTOR.replace("3.1","4.0"),"cvss_justification":"PRIVATE"},["cvss-profile-review"]),
])
def test_selected_report_quality(tmp_path,monkeypatch,changes,expected):
    _,report=native(tmp_path,monkeypatch,{"findings":[finding(**changes)]})
    assert keys(report) == expected
    assert "PRIVATE" not in json.dumps(report) and VECTOR not in json.dumps(report)
    assert not report["source_review"]["findings_removed_or_promoted"]
    if changes.get("verification_status") == "confirmed":
        assert report["records"][0]["verification_declaration"] == "confirmed" and not report["analyst_verdicts_verified"]


@pytest.mark.parametrize("change,duplicate",[({},True),({"test_case":"different"},False),({"test_role":"other"},False),
    ({"file_path":"other.py"},False),({"line_start":2},False),({"target_ref_hash":"b"*64},False)])
def test_duplicate_context_is_conservative_not_deletion(tmp_path,monkeypatch,change,duplicate):
    data={"findings":[finding(),finding(**change)]}
    before=copy.deepcopy(data)
    _,report=native(tmp_path,monkeypatch,data)
    assert keys(report) == (["possible-duplicate"] if duplicate else [])
    assert data == before and len(report["records"]) == 2


def test_missing_location_does_not_group_external_evidence(tmp_path,monkeypatch):
    _,report=native(tmp_path,monkeypatch,{"findings":[finding(file_path="external-evidence")]*2})
    assert not report["findings"]
    _,report=native(tmp_path,monkeypatch,{"findings":[finding(file_path="external-evidence",target_ref_hash="a"*64)]*2})
    assert keys(report) == ["possible-duplicate"]


@pytest.mark.parametrize("data",[{}, {"findings":[1]}, {"findings":[],"truncated":1},
    {"findings":[finding(title=1)]},{"findings":[finding(line_start=True)]},{"findings":[finding(evidence=True)]},
    {"findings":[finding(evidence=[{}]*21)]},{"findings":[finding(cvss_score=True)]},
    {"findings":[finding(cvss_score=10**400)]},{"findings":[finding(cvss_score=10.1)]},
    {"findings":[finding(title="x"*16385)]},{"findings":[finding(cvss_vector="x"*4097)]}])
def test_malformed_selected_report_fields_withhold_values(tmp_path,monkeypatch,data):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,data)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("raw",[b'{"findings":[],"findings":[]}',b'{"private":NaN}',b'{"ts":1e9999}',
    b'PRIVATE',b'\xff',b'['*45+b'0'+b']'*45,b' '*(MAX_BYTES+1),b'{"findings":[],"extra":['+b'0,'*60000+b'0]}'])
def test_json_parser_bounds_and_privacy(tmp_path,monkeypatch,raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_markdown_redacts_source_and_rejects_forged_fields(tmp_path,monkeypatch):
    _,report=native(tmp_path,monkeypatch,{"findings":[finding(title='[PRIVATE](https://PRIVATE.invalid)')]})
    output=render_markdown(report)
    assert "PRIVATE" not in output and "https://" not in output
    forged=copy.deepcopy(report)
    forged["records"][0]["case"]='[PRIVATE](https://PRIVATE.invalid)'
    with pytest.raises(ValueError):
        render_markdown(forged)
    forged=copy.deepcopy(report)
    forged["records"][0]["verification_declaration"]=[]
    with pytest.raises(ValueError):
        render_markdown(forged)


def test_no_network_process_or_evidence_resolution(tmp_path,monkeypatch):
    def deny(*args,**kwargs):
        pytest.fail("Offline reviewer attempted process/network access")
    monkeypatch.setattr(socket,"socket",deny)
    monkeypatch.setattr(socket,"getaddrinfo",deny)
    monkeypatch.setattr(subprocess,"Popen",deny)
    data={"findings":[finding()],"truncated":True}
    path,report=native(tmp_path,monkeypatch,data)
    original=path.read_bytes()
    assert report["input_sha256"] == hashlib.sha256(original).hexdigest() and path.read_bytes() == original
    assert keys(report) == ["source-truncated"] and "PRIVATE" not in json.dumps(report)
    assert cvss31(VECTOR)["base_score"] == 9.8


def test_cli_templates_catalog_index_sarif_and_nonoverwrite(tmp_path,monkeypatch,capsys):
    from hunterqa.coverage_audit import coverage_audit,render_checklist,render_category_index
    from hunterqa.sarif_export import export_sarif
    path=tmp_path/"evidence.json"
    path.write_bytes(Path("templates/HunterQA-utility-review-template.json").read_bytes())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    out=tmp_path/"report.json"
    main(["utility-review","--input",str(path),"--out",str(out),"--authorized"])
    assert json.loads(out.read_text())["status"] == "insufficient-evidence"
    with pytest.raises(FileExistsError):
        main(["utility-review","--input",str(path),"--out",str(out),"--authorized"])
    main(["utility-review-catalog"])
    output=capsys.readouterr().out
    assert all("offensive-"+k in output for k in PROFILES)
    main(["utility-cvss31","--vector",VECTOR])
    assert json.loads(capsys.readouterr().out)["base_score"] == 9.8
    assert Path("docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()
    assert Path("docs/CATEGORY_REVIEW_INDEX.md").read_text(encoding="utf-8") == render_category_index()
    audit=coverage_audit()
    assert not audit["all_seven_areas_complete"] and len(audit["category_packs"]) == 23
    assert sum(len(p["skills"]) for p in audit["category_packs"]) == 79
    assert all(not p["all_skills_automated"] for p in audit["category_packs"])
    path.write_bytes(Path("templates/HunterQA-report-quality-template.json").read_bytes())
    out=tmp_path/"quality.md"
    main(["utility-report-review","--input",str(path),"--out",str(out),"--format","markdown","--authorized"])
    assert out.read_text().startswith("# HunterQA report quality review")
    path,_=native(tmp_path,monkeypatch,{"findings":[finding(title=""),finding(title="",test_case="other")]})
    out=tmp_path/"quality.json"
    main(["utility-report-review","--input",str(path),"--out",str(out),"--authorized"])
    results=export_sarif(out)["runs"][0]["results"]
    assert len(results) == 2 and all("locations" not in r for r in results)
    assert results[0]["partialFingerprints"] != results[1]["partialFingerprints"]


def test_authorization_roots_symlinks_and_mode(tmp_path,monkeypatch):
    with pytest.raises(PermissionError):
        review_file(tmp_path/"absent")
    allowed=tmp_path/"allowed"
    allowed.mkdir()
    path,_=native(allowed,monkeypatch,{"findings":[]})
    with pytest.raises(ValueError):
        main(["utility-report-review","--input",str(path),"--out",str(tmp_path/"outside.json"),"--authorized"])
    assert not (tmp_path/"outside.json").exists()
    link=allowed/"link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        review_file(link,authorized=True)
    with pytest.raises(ValueError):
        review_file(path,authorized=True,mode="publish")
    other=tmp_path/"other"
    other.mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(other))
    with pytest.raises(ValueError):
        review_file(path,authorized=True)


def test_record_and_retention_bounds(tmp_path,monkeypatch):
    data={"schema_version":1,"records":[{"id":k+str(i),"skill":"offensive-"+k,"observations":dict.fromkeys(fs,None)} for k,fs in PROFILES.items() for i in range(10)]}
    assert len(review_evidence(data)["records"]) == 20
    data["records"].append({**data["records"][0],"id":"extra"})
    with pytest.raises(ValueError):
        review_evidence(data)
    _,report=native(tmp_path,monkeypatch,{"findings":[{}]*1000})
    assert len(report["records"]) == 1000 and len(report["findings"]) == 500
    assert report["truncated"] and report["candidates_not_retained"] == 3500
    with pytest.raises(ValueError):
        native(tmp_path,monkeypatch,{"findings":[{}]*1001})
