"""Owned saved DMARC/results fixtures; no messaging, targeting or collection."""
import copy
import hashlib
import json
import socket
import subprocess
import traceback
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.social_engineering_review import MAX_BYTES, PROFILES, review_evidence, review_file


def evidence(key="phishing",value=None):
    return {"schema_version":1,"records":[{"id":"owned-one","skill":"offensive-"+key,"observations":dict.fromkeys(PROFILES[key],value)}]}


def campaign(*rows,**fields):
    return {"results":list(rows),"name":"PRIVATE","url":"https://PRIVATE.invalid",**fields}


def native(tmp_path,monkeypatch,data,mode="gophish-results-json"):
    path=tmp_path/"inventory"
    path.write_bytes(data if isinstance(data,bytes) else (data.encode() if isinstance(data,str) else json.dumps(data).encode()))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    return path,review_file(path,authorized=True,mode=mode)


def keys(report):
    return [f["rule_id"].removeprefix("social-engineering-review.") for f in report["findings"]]


@pytest.mark.parametrize("key,field",[(k,f) for k,fs in PROFILES.items() for f in fs])
def test_contract_positive_negative_unknown(key,field):
    data=evidence(key,True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field]=False
    assert len(review_evidence(data)["findings"]) == 1
    report=review_evidence(evidence(key))
    assert report["status"] == "insufficient-evidence"
    assert report["network_requests"] == report["external_tools_executed"] == report["referenced_files_opened"] == 0
    assert not any(report[k] for k in ("live_mail_controls_verified","participant_behavior_verified","exercise_authorization_verified","all_skills_automated"))
    assert report["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change",[lambda d:d.update(schema_version=True),lambda d:d.update(schema_version=2),
    lambda d:d.update(records=[]),lambda d:d.update(extra="PRIVATE"),lambda d:d["records"][0].update(id="PRIVATE BAD"),
    lambda d:d["records"][0].update(skill=[]),lambda d:d["records"][0].update(observations={}),
    lambda d:d["records"][0]["observations"].update(owner_authorization_reviewed=1),
    lambda d:d["records"].append(copy.deepcopy(d["records"][0]))])
def test_strict_contract(change):
    data=evidence()
    change(data)
    with pytest.raises(ValueError,match="withheld"):
        review_evidence(data)


@pytest.mark.parametrize("text,expected",[
    ("v=DMARC1;p=none",["dmarc-p-none"]),
    ("v=DMARC1;p=reject;sp=none;np=none",["dmarc-sp-none","dmarc-np-none"]),
    ("v=DMARC1;p=reject;t=y",["dmarc-testing"]),
    ("v=DMARC1;p=reject;t=n",[]),
    ("v=DMARC1;p=quarantine;pct=50",["dmarc-legacy-pct"]),
    ("v=DMARC1;p=reject;pct=100",["dmarc-legacy-pct"]),
    ("v=DMARC1;p=reject;sp=reject;np=reject;adkim=s;aspf=r;rua=mailto:PRIVATE@PRIVATE.invalid;",[]),
    ("v=DMARC1;rua=mailto:PRIVATE@PRIVATE.invalid",[]),
    ("v=DMARC1",[]),
])
def test_selected_dmarc_rfc9989_declarations(tmp_path,monkeypatch,text,expected):
    _,report=native(tmp_path,monkeypatch,text,"dmarc-text")
    assert keys(report) == expected and "PRIVATE" not in json.dumps(report)
    assert not report["source_review"]["policy_defaults_or_inheritance_applied"]
    assert not report["source_review"]["spf_dkim_alignment_verified"]
    if ";p=" not in text:
        assert report["records"][0]["policy_declarations"]["p"] == "unknown"
    if text == "v=DMARC1":
        assert report["status"] == "insufficient-evidence"


@pytest.mark.parametrize("text",["", "PRIVATE", "p=reject;v=DMARC1", "v=dmarc1;p=reject",
    '"v=DMARC1;p=reject"', "v=DMARC1;p=reject;p=none", "v=DMARC1;p=PRIVATE", "v=DMARC1;t=PRIVATE",
    "v=DMARC1;pct=101", "v=DMARC1;pct=-1", "v=DMARC1;adkim=PRIVATE", "v=DMARC1;aspf=PRIVATE",
    "v=DMARC1;;p=reject", "v=DMARC1;PRIVATE", "v=DMARC1;x="+"x"*4097,
    "v=DMARC1;"+';'.join('tag'+str(i)+'=x' for i in range(100)), "x"*16385, "v=DMARC1;PRIVATE\x00"])
def test_dmarc_malformed_or_excessive_withholds_values(tmp_path,monkeypatch,text):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,text,"dmarc-text")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_dmarc_unknown_tags_and_bom(tmp_path,monkeypatch):
    _,report=native(tmp_path,monkeypatch,b'\xef\xbb\xbfv=DMARC1;p=reject;x=PRIVATE',"dmarc-text")
    assert report["source_review"]["unknown_tags_not_reviewed"] == 1
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("status,field",[("Email Sent","email_sent"),("Email Opened","email_opened"),
    ("Clicked Link","clicked_link"),("Submitted Data","submitted_data"),("PRIVATE","other_or_unknown"),(None,"other_or_unknown")])
def test_campaign_latest_status_is_not_cumulative(tmp_path,monkeypatch,status,field):
    _,report=native(tmp_path,monkeypatch,campaign({"status":status,"email":"PRIVATE@PRIVATE.invalid","id":"PRIVATE"}))
    row=report["records"][0]
    assert row["latest_status_counts"][field] == 1 and sum(row["latest_status_counts"].values()) == 1
    assert keys(report) == (["submitted-data-status"] if field == "submitted_data" else [])
    assert "PRIVATE" not in json.dumps(report)
    assert not report["source_review"]["cumulative_funnel_or_effectiveness_computed"]


def test_reporting_counts_are_independent_and_no_identity_leak(tmp_path,monkeypatch):
    data=campaign({"status":"Clicked Link","reported":True,"email":"PRIVATE","ip":"192.0.2.10"},
        {"status":"Email Sent","reported":False},{"status":None})
    _,report=native(tmp_path,monkeypatch,data)
    row=report["records"][0]
    assert row["reported_true_count"] == row["reported_false_count"] == row["reported_unknown_count"] == 1
    assert row["result_record_count"] == sum(row["latest_status_counts"].values()) == 3
    assert "PRIVATE" not in json.dumps(report) and "192.0.2.10" not in json.dumps(report)


@pytest.mark.parametrize("fields,expected",[
    ({"page":{"capture_credentials":True}},["simulation-capture-credentials"]),
    ({"page":{"capture_passwords":True}},["simulation-capture-passwords"]),
    ({"smtp":{"ignore_cert_errors":True,"username":"PRIVATE","password":"PRIVATE"}},["simulation-ignore-cert-errors"]),
    ({"page":{"capture_credentials":False,"capture_passwords":False},"smtp":{"ignore_cert_errors":False}},[]),
])
def test_saved_config_flags_do_not_collect_or_send(tmp_path,monkeypatch,fields,expected):
    _,report=native(tmp_path,monkeypatch,campaign(**fields))
    assert keys(report) == expected and "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("data",[{},[],{"results":{}},campaign(1),campaign({"status":1}),campaign({"reported":1}),
    campaign({"status":"PRIVATE\x00"}),campaign({"status":"x"*65}),campaign(page="PRIVATE"),
    campaign(page={"capture_passwords":"PRIVATE"}),campaign(smtp={"ignore_cert_errors":1}),
    campaign(*([{}]*1001))])
def test_bad_campaign_selected_values_withhold_input(tmp_path,monkeypatch,data):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,data)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("raw",[b'{"results":[],"results":[]}',b'{"private":NaN}',b'{"ts":1e9999}',
    b'PRIVATE',b'\xff',b'['*45+b'0'+b']'*45,b' '*(MAX_BYTES+1)])
def test_json_strict_parsing_and_bounds(tmp_path,monkeypatch,raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_no_network_process_delivery_or_credential_access(tmp_path,monkeypatch):
    def deny(*args,**kwargs):
        pytest.fail("Offline reviewer attempted process/network access")
    monkeypatch.setattr(socket,"socket",deny)
    monkeypatch.setattr(socket,"getaddrinfo",deny)
    monkeypatch.setattr(subprocess,"Popen",deny)
    data=campaign({"status":"Submitted Data","email":"PRIVATE"},timeline=[{"details":"PRIVATE"}],
        page={"html":"PRIVATE","capture_passwords":True},smtp={"host":"PRIVATE","password":"PRIVATE"})
    path,report=native(tmp_path,monkeypatch,data)
    original=path.read_bytes()
    assert report["input_sha256"] == hashlib.sha256(original).hexdigest()
    assert "PRIVATE" not in json.dumps(report) and path.read_bytes() == original
    _,report=native(tmp_path,monkeypatch,"v=DMARC1;p=reject;rua=mailto:PRIVATE@PRIVATE.invalid","dmarc-text")
    assert not report["source_review"]["dns_or_reporting_uris_resolved"]


def test_cli_template_catalog_coverage_sarif_and_nonoverwrite(tmp_path,monkeypatch,capsys):
    from hunterqa.coverage_audit import coverage_audit,render_checklist
    from hunterqa.sarif_export import export_sarif
    path=tmp_path/"evidence.json"
    path.write_bytes(Path("templates/HunterQA-social-review-template.json").read_bytes())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    out=tmp_path/"report.json"
    main(["social-review","--input",str(path),"--out",str(out),"--authorized"])
    assert json.loads(out.read_text())["status"] == "insufficient-evidence"
    with pytest.raises(FileExistsError):
        main(["social-review","--input",str(path),"--out",str(out),"--authorized"])
    main(["social-review-catalog"])
    output=capsys.readouterr().out
    assert all("offensive-"+k in output for k in PROFILES)
    assert Path("docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()
    assert not coverage_audit()["all_seven_areas_complete"]
    assert any(p["name"] == "Social Engineering" for p in coverage_audit()["category_packs"])
    path,_=native(tmp_path,monkeypatch,"v=DMARC1;p=none;sp=none","dmarc-text")
    out=tmp_path/"dmarc-report.json"
    main(["social-evidence-review","--mode","dmarc-text","--input",str(path),"--out",str(out),"--authorized"])
    results=export_sarif(out)["runs"][0]["results"]
    assert len(results) == 2 and all("locations" not in r for r in results)
    assert all(r["properties"]["verificationStatus"] == "unverified" for r in results)


def test_authorization_roots_symlinks_and_mode(tmp_path,monkeypatch):
    with pytest.raises(PermissionError):
        review_file(tmp_path/"absent")
    allowed=tmp_path/"allowed"
    allowed.mkdir()
    path,_=native(allowed,monkeypatch,campaign())
    with pytest.raises(ValueError):
        main(["social-evidence-review","--mode","gophish-results-json","--input",str(path),"--out",str(tmp_path/"outside.json"),"--authorized"])
    assert not (tmp_path/"outside.json").exists()
    link=allowed/"link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        review_file(link,authorized=True)
    with pytest.raises(ValueError):
        review_file(path,authorized=True,mode="send")
    other=tmp_path/"other"
    other.mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(other))
    with pytest.raises(ValueError):
        review_file(path,authorized=True)


def test_record_bounds_and_unknown_aggregate(tmp_path,monkeypatch):
    data={"schema_version":1,"records":[{"id":k+str(i),"skill":"offensive-"+k,"observations":dict.fromkeys(fs,None)} for k,fs in PROFILES.items() for i in range(10)]}
    assert len(review_evidence(data)["records"]) == 20
    data["records"].append({**data["records"][0],"id":"extra"})
    with pytest.raises(ValueError):
        review_evidence(data)
    data=evidence()
    data["records"]=[{**data["records"][0],"id":"case-"+str(i)} for i in range(11)]
    with pytest.raises(ValueError):
        review_evidence(data)
    _,report=native(tmp_path,monkeypatch,campaign(*([{"status":"PRIVATE"}]*1000)))
    assert report["status"] == "insufficient-evidence" and report["records"][0]["latest_status_counts"]["other_or_unknown"] == 1000
    assert len(report["records"]) == 1
