"""Owned saved privilege fixtures; never enumerate a host or change privileges."""
import copy
import hashlib
import json
import socket
import subprocess
import traceback
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.privilege_review import MAX_BYTES, PROFILES, review_evidence, review_file


def evidence(key="linux-privesc",value=None):
    return {"schema_version":1,"records":[{"id":"owned-one","skill":"offensive-"+key,"observations":dict.fromkeys(PROFILES[key],value)}]}


def native(tmp_path,monkeypatch,data,mode="windows-services-json"):
    path=tmp_path/"inventory"
    path.write_bytes(data if isinstance(data,bytes) else json.dumps(data).encode())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    return path,review_file(path,authorized=True,mode=mode)


def service(path=r"C:\PRIVATE folder\service.exe",**fields):
    return {"PathName":path,"StartName":"LocalSystem","StartMode":"Manual","ServiceType":"Own Process",**fields}


def keys(report):
    return [f["rule_id"].removeprefix("privilege-review.") for f in report["findings"]]


@pytest.mark.parametrize("key,field",[(k,f) for k,fs in PROFILES.items() for f in fs])
def test_contract_positive_negative_unknown(key,field):
    data=evidence(key,True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field]=False
    assert len(review_evidence(data)["findings"]) == 1
    report=review_evidence(evidence(key))
    assert report["status"] == "insufficient-evidence"
    assert report["network_requests"] == report["external_tools_executed"] == report["referenced_files_opened"] == 0
    assert not report["effective_permissions_verified"] and not report["privilege_escalation_verified"]
    assert not report["all_skills_automated"] and report["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change",[lambda d:d.update(schema_version=True),lambda d:d.update(schema_version=2),
    lambda d:d.update(records=[]),lambda d:d.update(extra="PRIVATE"),lambda d:d["records"][0].update(id="PRIVATE BAD"),
    lambda d:d["records"][0].update(skill=[]),lambda d:d["records"][0].update(observations={}),
    lambda d:d["records"][0]["observations"].update(sudo_policy_reviewed=1),
    lambda d:d["records"].append(copy.deepcopy(d["records"][0]))])
def test_strict_contract(change):
    data=evidence()
    change(data)
    with pytest.raises(ValueError,match="withheld"):
        review_evidence(data)


@pytest.mark.parametrize("line,count,selected,empty,skipped",[
    ("/PRIVATE cap_setuid=ep",1,1,False,0),
    ("/PRIVATE path cap_setuid,cap_dac_override=ep",1,2,False,0),
    ("/PRIVATE cap_setuid=p cap_sys_admin=i",1,2,False,0),
    ("/PRIVATE cap_net_bind_service=ep",1,0,False,0),
    ("/PRIVATE =",1,0,True,0),
    ("/PRIVATE cap_setuid=e [rootid=1000]",1,1,False,0),
    ("/PRIVATE cap_setuid=ee",0,0,False,1),
    ("/PRIVATE cap_setuid=p cap_setuid=i",0,0,False,1),
    ("/PRIVATE cap_setuid+p",0,0,False,1),
    ("/PRIVATE all=ep",0,0,False,1),
    ("/PRIVATE",0,0,False,1),
    ("PRIVATE: permission denied",0,0,False,1),
    ("",0,0,False,0),
])
def test_getcap_selected_and_unsupported(tmp_path,monkeypatch,line,count,selected,empty,skipped):
    _,report=native(tmp_path,monkeypatch,line.encode(),"getcap-text")
    assert len(report["records"]) == count
    assert report["source_review"]["unsupported_lines_not_reviewed"] == skipped
    assert len(report["findings"]) == bool(selected)
    if count:
        assert report["records"][0]["selected_capability_count"] == selected
        assert report["records"][0]["empty_capability_declaration"] == empty
    else:
        assert report["status"] == "insufficient-evidence"
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("path,kind,expected",[
    (r"C:\PRIVATE folder\service.exe","Own Process","unquoted-spaced-exe"),
    ('"C:\\PRIVATE folder\\service.exe" --arg PRIVATE',"Own Process","quoted-prefix-not-resolved"),
    (r"C:\PRIVATE\service.exe --arg PRIVATE","Share Process","unquoted-simple-exe"),
    (r"\\PRIVATE\shared folder\service.exe","Own Process","unquoted-spaced-exe"),
    (r"%PRIVATE%\service.exe","Own Process","unknown"),
    (r"C:\PRIVATE folder\service.sys","Kernel Driver","unknown"),
    (r"PRIVATE folder\service.exe","Own Process","unknown"),
    (r"C:\PRIVATE folder\service.exe",None,"unknown"),
    ('"C:\\PRIVATE folder\\service.exe',"Own Process","unknown"),
    (None,"Own Process","unknown"),
])
def test_windows_paths_context(tmp_path,monkeypatch,path,kind,expected):
    _,report=native(tmp_path,monkeypatch,service(path,ServiceType=kind,StartMode="Disabled"))
    row=report["records"][0]
    assert row["path_classification"] == expected
    assert row["local_system_name_declared"] is True and row["startup_declaration"] == "disabled"
    assert keys(report) == (["unquoted-service-path"] if expected == "unquoted-spaced-exe" else [])
    assert not row["effective_access_verified"] and "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("account,expected",[("LocalSystem",True),(r"NT AUTHORITY\SYSTEM",True),
    ("localsystem",True),(r"PRIVATE\admin",False),(None,None)])
def test_service_account_is_only_declaration(tmp_path,monkeypatch,account,expected):
    _,report=native(tmp_path,monkeypatch,service(StartName=account))
    assert report["records"][0]["local_system_name_declared"] is expected
    assert not report["effective_permissions_verified"]


@pytest.mark.parametrize("data",[{},[1],service(PathName=True),service(StartMode="PRIVATE"),
    service(StartName=[]),service(ServiceType=1),service(PathName="PRIVATE\x00"),service(PathName="x"*4097)])
def test_bad_selected_fields_hide_values(tmp_path,monkeypatch,data):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,data)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("raw",[b'{"PathName":null,"PathName":null}',b'{"private":NaN}',b'{"private":1e9999}',
    b'PRIVATE',b'\xff',b'['*45+b'0'+b']'*45,b' '*(MAX_BYTES+1)])
def test_json_bounds(tmp_path,monkeypatch,raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("raw",[b'\xff',b'PRIVATE\x00',b'x'*4097,b'\n'*1001])
def test_getcap_bounds(tmp_path,monkeypatch,raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,raw,"getcap-text")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_receipt_bom_privacy_and_no_execution(tmp_path,monkeypatch):
    def deny(*args,**kwargs):
        pytest.fail("Offline reviewer attempted process or network execution")
    monkeypatch.setattr(socket,"socket",deny)
    monkeypatch.setattr(socket,"getaddrinfo",deny)
    monkeypatch.setattr(subprocess,"Popen",deny)
    data=service(Name="PRIVATE",Description="PRIVATE",extra={"secret":"PRIVATE"})
    path,report=native(tmp_path,monkeypatch,b'\xef\xbb\xbf'+json.dumps(data).encode())
    assert report["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert "PRIVATE" not in json.dumps(report)
    assert all(f["severity"] == "INFO" and f["verification_status"] == "unverified" for f in report["findings"])
    _,report=native(tmp_path,monkeypatch,b'\xef\xbb\xbf/PRIVATE cap_sys_admin=ep\n',"getcap-text")
    assert keys(report) == ["selected-file-capabilities"]


def test_cli_catalog_template_sarif_and_coverage(tmp_path,monkeypatch,capsys):
    from hunterqa.coverage_audit import coverage_audit,render_checklist
    from hunterqa.sarif_export import export_sarif
    path=tmp_path/"evidence.json"
    path.write_bytes(Path("templates/HunterQA-privilege-review-template.json").read_bytes())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    out=tmp_path/"report.json"
    main(["privilege-review","--input",str(path),"--out",str(out),"--authorized"])
    assert json.loads(out.read_text())["status"] == "insufficient-evidence"
    with pytest.raises(FileExistsError):
        main(["privilege-review","--input",str(path),"--out",str(out),"--authorized"])
    main(["privilege-review-catalog"])
    assert "offensive-windows-privesc" in capsys.readouterr().out
    assert Path("docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()
    assert not coverage_audit()["all_seven_areas_complete"]
    assert any(p["name"] == "Privilege Escalation" for p in coverage_audit()["category_packs"])
    path,_=native(tmp_path,monkeypatch,[service(),service()])
    out=tmp_path/"service-report.json"
    main(["privilege-inventory-review","--mode","windows-services-json","--input",str(path),"--out",str(out),"--authorized"])
    results=export_sarif(out)["runs"][0]["results"]
    assert len(results) == 2 and all("locations" not in r for r in results)
    assert results[0]["partialFingerprints"] != results[1]["partialFingerprints"]


def test_authorization_roots_symlinks_and_mode(tmp_path,monkeypatch):
    with pytest.raises(PermissionError):
        review_file(tmp_path/"absent")
    path,_=native(tmp_path,monkeypatch,service())
    other=tmp_path/"other"
    other.mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(other))
    with pytest.raises(ValueError):
        review_file(path,authorized=True)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    link=tmp_path/"link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        review_file(link,authorized=True)
    with pytest.raises(ValueError):
        review_file(path,authorized=True,mode="live")


def test_record_and_finding_bounds(tmp_path,monkeypatch):
    data={"schema_version":1,"records":[{"id":k+str(i),"skill":"offensive-"+k,"observations":dict.fromkeys(fs,None)} for k,fs in PROFILES.items() for i in range(10)]}
    assert len(review_evidence(data)["records"]) == 20
    data["records"].append({**data["records"][0],"id":"extra"})
    with pytest.raises(ValueError):
        review_evidence(data)
    _,report=native(tmp_path,monkeypatch,[service()]*505)
    assert len(report["findings"]) == 500 and report["truncated"] and report["candidates_not_retained"] == 5
    with pytest.raises(ValueError):
        native(tmp_path,monkeypatch,[service()]*1001)
    _,report=native(tmp_path,monkeypatch,b'/PRIVATE cap_setuid=ep\n'*505,"getcap-text")
    assert len(report["findings"]) == 500 and report["candidates_not_retained"] == 5


@pytest.mark.parametrize("name",["cap_setuid","cap_setgid","cap_dac_override","cap_dac_read_search","cap_sys_admin","cap_sys_ptrace","cap_sys_module","cap_setpcap","cap_setfcap"])
def test_selected_capability_catalog(tmp_path,monkeypatch,name):
    _,report=native(tmp_path,monkeypatch,("/PRIVATE "+name+"=i [rootid=1000]").encode(),"getcap-text")
    assert len(report["findings"]) == 1 and report["records"][0]["namespace_root_id_declared"]
    assert not report["records"][0]["namespace_mapping_verified"]


def test_empty_or_unknown_saved_inventory(tmp_path,monkeypatch):
    _,report=native(tmp_path,monkeypatch,{"PathName":None})
    assert report["status"] == "insufficient-evidence"
    _,report=native(tmp_path,monkeypatch,[])
    assert report["status"] == "insufficient-evidence"


def test_output_root_and_private_permissions(tmp_path,monkeypatch):
    import os
    allowed=tmp_path/"allowed"
    allowed.mkdir()
    path=allowed/"inventory.json"
    path.write_text(json.dumps(service()))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(allowed))
    with pytest.raises(ValueError):
        main(["privilege-inventory-review","--mode","windows-services-json","--input",str(path),"--out",str(tmp_path/"outside.json"),"--authorized"])
    assert not (tmp_path/"outside.json").exists()
    out=allowed/"report.json"
    main(["privilege-inventory-review","--mode","windows-services-json","--input",str(path),"--out",str(out),"--authorized"])
    if os.name != "nt":
        assert out.stat().st_mode & 0o777 == 0o600
