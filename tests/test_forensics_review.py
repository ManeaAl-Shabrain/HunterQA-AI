"""Owned saved event/DNS fixtures; never alter evidence, deploy agents or contact endpoints."""
import copy
import hashlib
import json
import socket
import subprocess
import traceback
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.forensics_review import DEFAULT_LONG_QUERY_CHARS, EVENTS, MAX_BYTES, PROFILES, review_evidence, review_file

NS="http://schemas.microsoft.com/win/2004/08/events/event"


def evidence(key="anti-forensics",value=None):
    return {"schema_version":1,"records":[{"id":"owned-one","skill":"offensive-"+key,"observations":dict.fromkeys(PROFILES[key],value)}]}


def event(number=1102,provider=None,channel="Security",extra=""):
    provider=provider if provider is not None else EVENTS.get(number,("PRIVATE",))[0]
    return (f'<Event xmlns="{NS}"><System><Provider Name="{provider}"/><EventID>{number}</EventID><Channel>{channel}</Channel><Computer>PRIVATE</Computer></System>{extra}</Event>')


def dns(**changes):
    return json.dumps({"query":"PRIVATE.example","qtype_name":"A","rcode_name":"NOERROR","uid":"PRIVATE","id.orig_h":"192.0.2.10",**changes})


def native(tmp_path,monkeypatch,data,mode="zeek-dns-jsonl",**kwargs):
    path=tmp_path/"inventory"
    path.write_bytes(data if isinstance(data,bytes) else data.encode())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    return path,review_file(path,authorized=True,mode=mode,**kwargs)


def keys(report):
    return [f["rule_id"].removeprefix("forensics-review.") for f in report["findings"]]


@pytest.mark.parametrize("key,field",[(k,f) for k,fs in PROFILES.items() for f in fs])
def test_contract_positive_negative_unknown(key,field):
    data=evidence(key,True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field]=False
    assert len(review_evidence(data)["findings"]) == 1
    report=review_evidence(evidence(key))
    assert report["status"] == "insufficient-evidence"
    assert report["network_requests"] == report["external_tools_executed"] == report["referenced_files_opened"] == 0
    assert not any(report[k] for k in ("evidence_integrity_verified","malicious_activity_verified","c2_attribution_verified","all_skills_automated"))
    assert report["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change",[lambda d:d.update(schema_version=True),lambda d:d.update(schema_version=2),
    lambda d:d.update(records=[]),lambda d:d.update(extra="PRIVATE"),lambda d:d["records"][0].update(id="PRIVATE BAD"),
    lambda d:d["records"][0].update(skill=[]),lambda d:d["records"][0].update(observations={}),
    lambda d:d["records"][0]["observations"].update(log_retention_reviewed=1),
    lambda d:d["records"].append(copy.deepcopy(d["records"][0]))])
def test_strict_contract(change):
    data=evidence()
    change(data)
    with pytest.raises(ValueError,match="withheld"):
        review_evidence(data)


@pytest.mark.parametrize("number",list(EVENTS))
@pytest.mark.parametrize("wrapper",[None,"Events",'{ns}Events'])
def test_selected_event_provider_channel_and_wrapper(tmp_path,monkeypatch,number,wrapper):
    text=event(number,extra="<EventData><Data>PRIVATE</Data></EventData>")
    if wrapper:
        text=('<Events xmlns="'+NS+'">' if wrapper.startswith('{') else '<Events>')+text+'</Events>'
    _,report=native(tmp_path,monkeypatch,text,"windows-events-xml")
    assert keys(report) == [EVENTS[number][1]]
    assert report["records"][0]["selected_provider_and_channel_matched"]
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("text",[event(provider="PRIVATE"),event(channel="System"),event(4624),
    '<Event xmlns="'+NS+'"/>','<Event xmlns="'+NS+'"><System><EventID>1102</EventID></System></Event>',
    '<Events/>','<Events><PRIVATE/></Events>'])
def test_unmatched_missing_or_unrelated_context(tmp_path,monkeypatch,text):
    _,report=native(tmp_path,monkeypatch,text,"windows-events-xml")
    assert not report["findings"] and report["status"] == "insufficient-evidence"
    if "<PRIVATE/>" in text:
        assert report["source_review"]["unsupported_elements_not_reviewed"] == 1


@pytest.mark.parametrize("raw",[b'PRIVATE',b'\xff',b'<Event xmlns="urn:PRIVATE"/>',
    event().replace('<EventID>1102</EventID>','<EventID>PRIVATE</EventID>').encode(),
    event().replace('<EventID>1102</EventID>','<EventID>65536</EventID>').encode(),
    event().replace('<EventID>1102</EventID>','<EventID>1102</EventID><EventID>1102</EventID>').encode(),
    event().replace('<System>','<System/><System>').encode(),
    event().replace('<Provider Name="Microsoft-Windows-Eventlog"/>','<Provider/><Provider/>').encode(),
    ('<Events>'+event()*1001+'</Events>').encode(),
    event(extra='<x>'*41+'</x>'*41).encode(),event(extra='<x/>'*20001).encode(),
    b'<!DOCTYPE Event [<!ENTITY p "PRIVATE">]><Event>&p;</Event>',
    b'<!DOCTYPE Event SYSTEM "https://PRIVATE.invalid/"><Event/>'])
def test_event_xml_bounds_and_sanitized_errors(tmp_path,monkeypatch,raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,raw,"windows-events-xml")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("changes,expected",[
    ({},[]),({"qtype_name":"TXT"},["txt-query"]),({"qtype_name":"txt","rejected":True},["txt-query"]),
    ({"query":"x"*(DEFAULT_LONG_QUERY_CHARS-1)},[]),
    ({"query":"x"*DEFAULT_LONG_QUERY_CHARS},["long-query"]),
    ({"query":"x"*DEFAULT_LONG_QUERY_CHARS+".","qtype_name":"TXT"},["txt-query","long-query"]),
    ({"query":None,"qtype_name":None,"rcode_name":None},[]),
    ({"query":"-","qtype_name":None,"rcode_name":"NXDOMAIN"},[]),
])
def test_dns_matches_nonmatches_and_unknowns(tmp_path,monkeypatch,changes,expected):
    _,report=native(tmp_path,monkeypatch,dns(**changes))
    assert keys(report) == expected
    assert not report["source_review"]["aggregation_or_timing_analysis_performed"]
    assert "PRIVATE" not in json.dumps(report) and "192.0.2.10" not in json.dumps(report)
    if all(v is None for v in changes.values()) and changes:
        assert report["status"] == "insufficient-evidence"
    if changes.get("rcode_name") == "NXDOMAIN":
        assert report["records"][0]["response_class"] == "nxdomain"


@pytest.mark.parametrize("changes",[{"query":True},{"qtype_name":1},{"rcode_name":[]},{"rejected":1},
    {"query":"PRIVATE\x00"},{"query":"x"*4097},{"qtype_name":"x"*33},{"rcode_name":"x"*33}])
def test_dns_bad_selected_values_withhold_input(tmp_path,monkeypatch,changes):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,dns(**changes))
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("raw",[b'{"query":null,"query":null}',b'{"query":NaN}',b'{"ts":1e9999}',
    b'PRIVATE',b'\xff',b'['*45+b'0'+b']'*45,b' '*(MAX_BYTES+1),b'x'*16385,b'\n'*1001])
def test_jsonl_strict_parsing_and_bounds(tmp_path,monkeypatch,raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("value",[True,0,-1,4097,"PRIVATE"])
def test_threshold_rejected_before_read(tmp_path,value):
    with pytest.raises(ValueError,match="withheld"):
        review_file(tmp_path/"absent",authorized=True,mode="zeek-dns-jsonl",long_query_chars=value)


def test_unsupported_json_rows_and_custom_threshold(tmp_path,monkeypatch):
    _,report=native(tmp_path,monkeypatch,'\n'.join(['{}','[]',dns(query="xxxx")]),long_query_chars=4)
    assert report["source_review"]["unsupported_rows_not_reviewed"] == 2
    assert report["source_review"]["long_query_threshold_chars"] == 4
    assert keys(report) == ["long-query"]


def test_no_network_process_or_external_resolution(tmp_path,monkeypatch):
    def deny(*args,**kwargs):
        pytest.fail("Offline reviewer attempted network/process execution")
    monkeypatch.setattr(socket,"socket",deny)
    monkeypatch.setattr(socket,"getaddrinfo",deny)
    monkeypatch.setattr(subprocess,"Popen",deny)
    raw=event(extra='<UserData><PRIVATE>PRIVATE</PRIVATE></UserData>').encode()
    path,report=native(tmp_path,monkeypatch,raw,"windows-events-xml")
    assert report["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert "PRIVATE" not in json.dumps(report) and path.read_bytes() == raw
    with pytest.raises(ValueError,match="withheld"):
        native(tmp_path,monkeypatch,b'<!DOCTYPE Event SYSTEM "https://PRIVATE.invalid/"><Event/>',"windows-events-xml")
    _,report=native(tmp_path,monkeypatch,b'\xef\xbb\xbf'+dns(qtype_name="TXT").encode())
    assert keys(report) == ["txt-query"]


def test_cli_template_catalog_coverage_sarif_and_nonoverwrite(tmp_path,monkeypatch,capsys):
    from hunterqa.coverage_audit import coverage_audit,render_checklist
    from hunterqa.sarif_export import export_sarif
    path=tmp_path/"evidence.json"
    path.write_bytes(Path("templates/HunterQA-forensics-review-template.json").read_bytes())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    out=tmp_path/"report.json"
    main(["forensics-review","--input",str(path),"--out",str(out),"--authorized"])
    assert json.loads(out.read_text())["status"] == "insufficient-evidence"
    with pytest.raises(FileExistsError):
        main(["forensics-review","--input",str(path),"--out",str(out),"--authorized"])
    main(["forensics-review-catalog"])
    output=capsys.readouterr().out
    assert all("offensive-"+k in output for k in PROFILES)
    assert Path("docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()
    assert not coverage_audit()["all_seven_areas_complete"]
    assert any(p["name"] == "Forensics & C2" for p in coverage_audit()["category_packs"])
    path,_=native(tmp_path,monkeypatch,dns(qtype_name="TXT")+'\n'+dns(qtype_name="TXT"))
    out=tmp_path/"dns-report.json"
    main(["forensics-log-review","--mode","zeek-dns-jsonl","--long-query-chars","80","--input",str(path),"--out",str(out),"--authorized"])
    results=export_sarif(out)["runs"][0]["results"]
    assert len(results) == 2 and all("locations" not in r for r in results)
    assert results[0]["partialFingerprints"] != results[1]["partialFingerprints"]


def test_authorization_roots_symlinks_and_mode(tmp_path,monkeypatch):
    with pytest.raises(PermissionError):
        review_file(tmp_path/"absent")
    allowed=tmp_path/"allowed"
    allowed.mkdir()
    path,_=native(allowed,monkeypatch,dns())
    with pytest.raises(ValueError):
        main(["forensics-log-review","--mode","zeek-dns-jsonl","--input",str(path),"--out",str(tmp_path/"outside.json"),"--authorized"])
    assert not (tmp_path/"outside.json").exists()
    link=allowed/"link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        review_file(link,authorized=True)
    with pytest.raises(ValueError):
        review_file(path,authorized=True,mode="live")
    other=tmp_path/"other"
    other.mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(other))
    with pytest.raises(ValueError):
        review_file(path,authorized=True)


def test_record_and_retention_limits(tmp_path,monkeypatch):
    data={"schema_version":1,"records":[{"id":k+str(i),"skill":"offensive-"+k,"observations":dict.fromkeys(fs,None)} for k,fs in PROFILES.items() for i in range(10)]}
    assert len(review_evidence(data)["records"]) == 20
    data["records"].append({**data["records"][0],"id":"extra"})
    with pytest.raises(ValueError):
        review_evidence(data)
    data=evidence()
    data["records"]=[{**data["records"][0],"id":"case-"+str(i)} for i in range(11)]
    with pytest.raises(ValueError):
        review_evidence(data)
    _,report=native(tmp_path,monkeypatch,'\n'.join([dns(query="x"*80,qtype_name="TXT")]*1000))
    assert len(report["findings"]) == 500 and report["truncated"] and report["candidates_not_retained"] == 1500
    _,report=native(tmp_path,monkeypatch,'<Events>'+event()*505+'</Events>',"windows-events-xml")
    assert len(report["findings"]) == 500 and report["candidates_not_retained"] == 5
