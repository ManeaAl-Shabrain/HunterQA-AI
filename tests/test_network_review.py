"""Owned saved network configurations; no packets, queries or host changes."""
import copy
import hashlib
import json
import socket
import subprocess
import traceback
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.network_review import MAX_BYTES, PROFILES, review_evidence, review_file


def evidence(value=None):
    return {"schema_version":1,"records":[{"id":"owned-one","skill":"offensive-network-attacks","observations":dict.fromkeys(PROFILES["network-attacks"],value)}]}


def native(tmp_path,monkeypatch,data,mode="sysctl-text"):
    path=tmp_path/"inventory"
    path.write_bytes(data if isinstance(data,bytes) else (data.encode() if isinstance(data,str) else json.dumps(data).encode()))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    return path,review_file(path,authorized=True,mode=mode)


def keys(report):
    return [f["rule_id"].removeprefix("network-review.") for f in report["findings"]]


@pytest.mark.parametrize("field",PROFILES["network-attacks"])
def test_contract_positive_negative_unknown(field):
    data=evidence(True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field]=False
    assert len(review_evidence(data)["findings"]) == 1
    report=review_evidence(evidence())
    assert report["status"] == "insufficient-evidence"
    assert report["network_requests"] == report["external_tools_executed"] == report["referenced_files_opened"] == 0
    assert not any(report[k] for k in ("effective_interface_policy_verified","network_topology_verified","exploitability_verified","all_skills_automated"))
    assert report["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change",[lambda d:d.update(schema_version=True),lambda d:d.update(schema_version=2),
    lambda d:d.update(records=[]),lambda d:d.update(extra="PRIVATE"),lambda d:d["records"][0].update(id="PRIVATE BAD"),
    lambda d:d["records"][0].update(skill=[]),lambda d:d["records"][0].update(observations={}),
    lambda d:d["records"][0]["observations"].update(arp_inspection_reviewed=1),
    lambda d:d["records"].append(copy.deepcopy(d["records"][0]))])
def test_strict_contract(change):
    data=evidence()
    change(data)
    with pytest.raises(ValueError,match="withheld"):
        review_evidence(data)


@pytest.mark.parametrize("key,value,flag",[
    ("net.ipv4.ip_forward",1,True),("net.ipv4.ip_forward",0,False),
    ("net.ipv4.conf.all.accept_redirects",1,True),("net.ipv4.conf.all.accept_redirects",0,False),
    ("net.ipv4.conf.default.accept_source_route",1,True),("net.ipv4.conf.default.accept_source_route",0,False),
    ("net.ipv4.conf.PRIVATE.send_redirects",1,True),("net.ipv4.conf.PRIVATE.send_redirects",0,False),
    ("net.ipv4.conf.PRIVATE.secure_redirects",0,True),("net.ipv4.conf.PRIVATE.secure_redirects",1,False),
    ("net.ipv4.conf.PRIVATE.rp_filter",0,True),("net.ipv4.conf.PRIVATE.rp_filter",1,False),("net.ipv4.conf.PRIVATE.rp_filter",2,False),
    ("net.ipv6.conf.PRIVATE.accept_redirects",1,True),("net.ipv6.conf.PRIVATE.accept_redirects",0,False),
    ("net.ipv6.conf.PRIVATE.accept_ra",2,True),("net.ipv6.conf.PRIVATE.accept_ra",1,False),("net.ipv6.conf.PRIVATE.accept_ra",0,False),
    ("net.ipv6.conf.all.forwarding",1,True),("net.ipv6.conf.all.forwarding",0,False),
])
def test_selected_sysctl_values_are_declarations_only(tmp_path,monkeypatch,key,value,flag):
    _,report=native(tmp_path,monkeypatch,key+' = '+str(value))
    assert len(report["findings"]) == int(flag)
    assert report["records"][0]["integer_declaration"] == value
    assert not report["records"][0]["effective_combination_computed"]
    assert not report["source_review"]["role_or_effective_policy_computed"]
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("key,scope",[("net.ipv4.ip_forward","global"),
    ("net.ipv4.conf.all.accept_redirects","all"),("net.ipv4.conf.default.accept_redirects","default"),
    ("net.ipv4.conf.global.accept_redirects","interface"),("net.ipv4.conf.PRIVATE.accept_redirects","interface")])
def test_scope_labels_do_not_export_interface_names(tmp_path,monkeypatch,key,scope):
    _,report=native(tmp_path,monkeypatch,key+'=1')
    assert report["records"][0]["scope_class"] == scope


@pytest.mark.parametrize("line",["net.ipv6.conf.all.accept_source_route=-1","net.ipv6.conf.all.accept_source_route=0",
    "net/ipv4/conf/all/rp_filter=0","net.ipv4.conf.eth0.100.rp_filter=0","-net.ipv4.ip_forward=1", "PRIVATE=PRIVATE"])
def test_unsupported_syntax_is_counted_not_interpreted(tmp_path,monkeypatch,line):
    _,report=native(tmp_path,monkeypatch,line)
    assert report["source_review"]["unsupported_assignments_not_reviewed"] == 1
    assert report["status"] == "insufficient-evidence" and not report["findings"]
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("line",["net.ipv4.ip_forward=PRIVATE","net.ipv4.ip_forward=-1","net.ipv4.ip_forward=2",
    "net.ipv4.conf.all.rp_filter=3","net.ipv6.conf.all.accept_ra=3","net.ipv4.ip_forward=1 # PRIVATE",
    "net.ipv4.ip_forward=1\nnet.ipv4.ip_forward=0","net.ipv4.ip_forward"])
def test_malformed_selected_sysctl_values_fail(tmp_path,monkeypatch,line):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,line)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("key,value,expected",[
    ("LLMNR","yes",True),("LLMNR","resolve",True),("LLMNR","no",False),
    ("MulticastDNS","yes",True),("MulticastDNS","resolve",True),("MulticastDNS","no",False),
    ("DNSSEC","yes",False),("DNSSEC","no",True),("DNSSEC","allow-downgrade",True),
    ("DNSOverTLS","yes",False),("DNSOverTLS","no",True),("DNSOverTLS","opportunistic",True),
])
def test_selected_resolver_modes(tmp_path,monkeypatch,key,value,expected):
    _,report=native(tmp_path,monkeypatch,'[Resolve]\n'+key+'='+value,"resolved-conf")
    assert len(report["findings"]) == int(expected)
    assert report["records"][0]["mode_declaration"] == value
    assert not report["records"][0]["per_link_or_dropin_policy_resolved"]


@pytest.mark.parametrize("value,expected",[("true","yes"),("on","yes"),("1","yes"),("false","no"),("off","no"),("0","no"),("","unknown")])
def test_resolver_boolean_forms_and_reset_unknown(tmp_path,monkeypatch,value,expected):
    _,report=native(tmp_path,monkeypatch,'[Resolve]\nLLMNR='+value,"resolved-conf")
    assert report["records"][0]["mode_declaration"] == expected
    if not value:
        assert report["status"] == "insufficient-evidence" and not report["findings"]


@pytest.mark.parametrize("text",["PRIVATE","[Resolve]\nLLMNR=PRIVATE","[Resolve]\nDNSSEC=opportunistic",
    "[Resolve]\nDNSOverTLS=resolve","[Resolve]\nLLMNR=yes\nLLMNR=no","[Resolve]\n[Resolve]",
    "[DEFAULT]\nPRIVATE=PRIVATE\n[Resolve]"])
def test_malformed_selected_resolver_values_fail(tmp_path,monkeypatch,text):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,text,"resolved-conf")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_resolver_case_and_private_unknown_values(tmp_path,monkeypatch):
    _,report=native(tmp_path,monkeypatch,'[Resolve]\nDNS=192.0.2.10\nllmnr=yes\n[resolve]\nLLMNR=yes',"resolved-conf")
    assert report["source_review"]["unsupported_settings_not_reviewed"] == 3
    assert report["status"] == "insufficient-evidence" and not report["findings"]
    assert "192.0.2.10" not in json.dumps(report)


@pytest.mark.parametrize("raw",[b'{"records":[],"records":[]}',b'{"private":NaN}',b'{"ts":1e9999}',
    b'PRIVATE',b'\xff',b'['*45+b'0'+b']'*45,b' '*(MAX_BYTES+1)])
def test_json_strict_parsing_and_bounds(tmp_path,monkeypatch,raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,raw,"normalized")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("raw",[b'\xff',b'PRIVATE\x00',b'x'*4097,b'\n'*1001])
@pytest.mark.parametrize("mode",["sysctl-text","resolved-conf"])
def test_text_bounds(tmp_path,monkeypatch,raw,mode):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,raw,mode)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_no_network_process_or_runtime_access(tmp_path,monkeypatch):
    def deny(*args,**kwargs):
        pytest.fail("Offline reviewer attempted network/process execution")
    monkeypatch.setattr(socket,"socket",deny)
    monkeypatch.setattr(socket,"getaddrinfo",deny)
    monkeypatch.setattr(subprocess,"Popen",deny)
    raw=b'\xef\xbb\xbfnet.ipv4.conf.PRIVATE.accept_redirects=1\n'
    path,report=native(tmp_path,monkeypatch,raw)
    assert report["input_sha256"] == hashlib.sha256(raw).hexdigest() and path.read_bytes() == raw
    assert "PRIVATE" not in json.dumps(report)
    _,report=native(tmp_path,monkeypatch,'[Resolve]\nDNS=PRIVATE\nLLMNR=yes',"resolved-conf")
    assert len(report["findings"]) == 1 and "PRIVATE" not in json.dumps(report)


def test_cli_template_catalog_coverage_sarif_and_nonoverwrite(tmp_path,monkeypatch,capsys):
    from hunterqa.coverage_audit import coverage_audit,render_checklist
    from hunterqa.sarif_export import export_sarif
    path=tmp_path/"evidence.json"
    path.write_bytes(Path("templates/HunterQA-network-review-template.json").read_bytes())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    out=tmp_path/"report.json"
    main(["network-review","--input",str(path),"--out",str(out),"--authorized"])
    assert json.loads(out.read_text())["status"] == "insufficient-evidence"
    with pytest.raises(FileExistsError):
        main(["network-review","--input",str(path),"--out",str(out),"--authorized"])
    main(["network-review-catalog"])
    assert "offensive-network-attacks" in capsys.readouterr().out
    assert Path("docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()
    assert not coverage_audit()["all_seven_areas_complete"]
    assert any(p["name"] == "Network" for p in coverage_audit()["category_packs"])
    path,_=native(tmp_path,monkeypatch,'net.ipv4.conf.PRIVATE.accept_redirects=1\nnet.ipv4.conf.OTHER.accept_redirects=1')
    out=tmp_path/"config-report.json"
    main(["network-config-review","--mode","sysctl-text","--input",str(path),"--out",str(out),"--authorized"])
    results=export_sarif(out)["runs"][0]["results"]
    assert len(results) == 2 and all("locations" not in r for r in results)
    assert results[0]["partialFingerprints"] != results[1]["partialFingerprints"]


def test_authorization_roots_symlinks_and_mode(tmp_path,monkeypatch):
    with pytest.raises(PermissionError):
        review_file(tmp_path/"absent")
    allowed=tmp_path/"allowed"
    allowed.mkdir()
    path,_=native(allowed,monkeypatch,"net.ipv4.ip_forward=0")
    with pytest.raises(ValueError):
        main(["network-config-review","--mode","sysctl-text","--input",str(path),"--out",str(tmp_path/"outside.json"),"--authorized"])
    assert not (tmp_path/"outside.json").exists()
    link=allowed/"link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        review_file(link,authorized=True)
    with pytest.raises(ValueError):
        review_file(path,authorized=True,mode="spoof")
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
    _,report=native(tmp_path,monkeypatch,'\n'.join('net.ipv4.conf.if'+str(i)+'.accept_redirects=1' for i in range(1000)))
    assert len(report["records"]) == 1000 and len(report["findings"]) == 500
    assert report["truncated"] and report["candidates_not_retained"] == 500
