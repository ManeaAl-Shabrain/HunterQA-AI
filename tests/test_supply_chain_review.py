"""Owned saved package/config fixtures; never install, publish or resolve packages."""
import base64
import copy
import hashlib
import json
import socket
import subprocess
import traceback
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.supply_chain_review import MAX_BYTES, PROFILES, review_evidence, review_file


def evidence(key="supply-chain",value=None):
    return {"schema_version":1,"records":[{"id":"owned-one","skill":"offensive-"+key,"observations":dict.fromkeys(PROFILES[key],value)}]}


def digest(algorithm="sha512"):
    return algorithm+'-'+base64.b64encode(b'x'*{"sha1":20,"sha256":32,"sha384":48,"sha512":64}[algorithm]).decode()


def lock(**fields):
    return {"lockfileVersion":3,"packages":{"":{},"node_modules/PRIVATE":{"resolved":"https://PRIVATE.invalid/PRIVATE.tgz","integrity":digest(),**fields}}}


def native(tmp_path,monkeypatch,data,mode="npm-lock-json"):
    path=tmp_path/"inventory"
    path.write_bytes(data if isinstance(data,bytes) else (data.encode() if isinstance(data,str) else json.dumps(data).encode()))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    return path,review_file(path,authorized=True,mode=mode)


def keys(report):
    return [f["rule_id"].removeprefix("supply-chain-review.") for f in report["findings"]]


@pytest.mark.parametrize("key,field",[(k,f) for k,fs in PROFILES.items() for f in fs])
def test_contract_positive_negative_unknown(key,field):
    data=evidence(key,True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field]=False
    assert len(review_evidence(data)["findings"]) == 1
    report=review_evidence(evidence(key))
    assert report["status"] == "insufficient-evidence"
    assert report["network_requests"] == report["external_tools_executed"] == report["referenced_files_opened"] == 0
    assert not any(report[k] for k in ("artifact_authenticity_verified","effective_resolution_verified","namespace_ownership_verified","all_skills_automated"))
    assert report["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change",[lambda d:d.update(schema_version=True),lambda d:d.update(schema_version=2),
    lambda d:d.update(records=[]),lambda d:d.update(extra="PRIVATE"),lambda d:d["records"][0].update(id="PRIVATE BAD"),
    lambda d:d["records"][0].update(skill=[]),lambda d:d["records"][0].update(observations={}),
    lambda d:d["records"][0]["observations"].update(dependency_inventory_reviewed=1),
    lambda d:d["records"].append(copy.deepcopy(d["records"][0]))])
def test_strict_contract(change):
    data=evidence()
    change(data)
    with pytest.raises(ValueError,match="withheld"):
        review_evidence(data)


@pytest.mark.parametrize("value,state,flag",[(digest(a),"recognized-strong-shape",False) for a in ("sha256","sha384","sha512")]+[
    (digest("sha1"),"recognized-legacy-shape",True),(None,"missing",True),("","missing",True),
    ("sha512-PRIVATE","unrecognized-shape",True),("sha512-"+base64.b64encode(b'x'*10).decode(),"unrecognized-shape",True),
    (digest()+" "+digest("sha1"),"recognized-strong-shape",False),
    (digest()+"?PRIVATE","unrecognized-shape",True)])
def test_integrity_shape_is_not_verification(tmp_path,monkeypatch,value,state,flag):
    _,report=native(tmp_path,monkeypatch,lock(integrity=value))
    assert report["records"][0]["integrity_declaration"] == state
    assert keys(report) == (["archive-integrity-review"] if flag else [])
    assert not report["records"][0]["artifact_digest_compared"] and "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("fields,expected",[
    ({"resolved":"http://PRIVATE.invalid/x"},["plain-http-source"]),
    ({"resolved":"https://PRIVATE:PRIVATE@PRIVATE.invalid/x"},["url-user-information"]),
    ({"hasInstallScript":True},["install-script-declaration"]),
    ({"hasInstallScript":False},[]),({"link":True,"integrity":None},[]),
    ({"resolved":"file:../PRIVATE","integrity":None},[]),
    ({"resolved":"${PRIVATE}/x","integrity":None},[]),
    ({"resolved":None,"integrity":None},[]),
])
def test_npm_sources_scripts_links_unknowns(tmp_path,monkeypatch,fields,expected):
    _,report=native(tmp_path,monkeypatch,lock(**fields))
    assert keys(report) == expected and report["source_review"]["root_metadata_entries_not_reviewed"] == 1
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("data",[{}, {"lockfileVersion":True,"packages":{}},{"lockfileVersion":1,"packages":{}},
    {"lockfileVersion":3,"packages":[]},lock(hasInstallScript=1),lock(link="PRIVATE"),lock(integrity=[]),
    lock(resolved="https://[PRIVATE"),lock(resolved="https:///PRIVATE"),lock(resolved="PRIVATE\x00")])
def test_bad_lock_selected_values_withhold_input(tmp_path,monkeypatch,data):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,data)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("text,expected",[
    ("registry=https://PRIVATE.invalid\n@PRIVATE:registry=https://PRIVATE.invalid\n",[]),
    ("registry=http://PRIVATE.invalid",["plain-http-source"]),
    ('registry="https://PRIVATE:PRIVATE@PRIVATE.invalid/x"',["url-user-information"]),
    ("strict-ssl=false",["npmrc-strict-ssl"]),("ignore-scripts=false",["npmrc-ignore-scripts"]),
    ("package-lock=false",["npmrc-package-lock"]),("strict-ssl=true\nignore-scripts=true\npackage-lock=true",[]),
    ("registry=${PRIVATE}\nstrict-ssl=${PRIVATE}",[]),
    ("//PRIVATE.invalid/:_authToken=PRIVATE\n# PRIVATE\n; PRIVATE",[]),
])
def test_npmrc_selected_literals_and_redaction(tmp_path,monkeypatch,text,expected):
    _,report=native(tmp_path,monkeypatch,text,"npmrc-text")
    assert keys(report) == expected and "PRIVATE" not in json.dumps(report)
    assert not report["source_review"]["config_precedence_or_environment_resolved"]


@pytest.mark.parametrize("text",["registry=https://PRIVATE.invalid\nregistry=https://PRIVATE.invalid", "strict-ssl=PRIVATE",
    "package-lock=false # PRIVATE", "registry=https://[PRIVATE"])
def test_npmrc_malformed_selected_inputs(tmp_path,monkeypatch,text):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,text,"npmrc-text")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("text,expected",[
    ("[global]\nindex-url=https://PRIVATE.invalid/simple\nrequire-hashes=yes\nno-index=true",[]),
    ("[global]\nextra-index-url=https://PRIVATE.invalid/simple",["pip-extra-index"]),
    ("[global]\nextra-index-url=\n    https://PRIVATE.invalid/simple\n    https://OTHER.invalid/simple",["pip-extra-index"]),
    ("[install]\ntrusted-host=PRIVATE.invalid",["pip-trusted-host"]),
    ("[download]\nrequire-hashes=no",["pip-hashes-disabled"]),
    ("[wheel]\nindex-url=http://PRIVATE.invalid",["plain-http-source"]),
    ("[global]\nindex-url=https://PRIVATE:PRIVATE@PRIVATE.invalid/simple",["url-user-information"]),
    ("[PRIVATE]\nindex-url=http://PRIVATE.invalid",[]),
    ("[global]\nindex-url=${PRIVATE}",[]),
])
def test_pip_selected_declarations(tmp_path,monkeypatch,text,expected):
    _,report=native(tmp_path,monkeypatch,text,"pip-conf")
    assert keys(report) == expected and "PRIVATE" not in json.dumps(report)
    assert not report["source_review"]["config_precedence_or_environment_resolved"]


@pytest.mark.parametrize("text",["PRIVATE", "[global]\nindex-url=https://PRIVATE.invalid\nindex-url=PRIVATE",
    "[global]\n[global]\nindex-url=PRIVATE", "[DEFAULT]\nPRIVATE=PRIVATE\n[global]",
    "[global]\nrequire-hashes=PRIVATE", "[global]\nindex-url=https://PRIVATE.invalid https://PRIVATE.invalid",
    "[global]\nextra-index-url="+" ".join(["https://PRIVATE.invalid"]*21)])
def test_pip_malformed_selected_input(tmp_path,monkeypatch,text):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,text,"pip-conf")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("raw",[b'{"packages":{},"packages":{}}',b'{"private":NaN}',b'{"ts":1e9999}',
    b'PRIVATE',b'\xff',b'['*45+b'0'+b']'*45,b' '*(MAX_BYTES+1)])
def test_json_strict_parsing_and_bounds(tmp_path,monkeypatch,raw):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("raw",[b'\xff',b'PRIVATE\x00',b'x'*4097,b'\n'*1001])
@pytest.mark.parametrize("mode",["npmrc-text","pip-conf"])
def test_text_bounds(tmp_path,monkeypatch,raw,mode):
    with pytest.raises(ValueError) as exc:
        native(tmp_path,monkeypatch,raw,mode)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_no_network_process_or_config_expansion(tmp_path,monkeypatch):
    def deny(*args,**kwargs):
        pytest.fail("Offline reviewer attempted registry/process access")
    monkeypatch.setattr(socket,"socket",deny)
    monkeypatch.setattr(socket,"getaddrinfo",deny)
    monkeypatch.setattr(subprocess,"Popen",deny)
    monkeypatch.setenv("PRIVATE","http://PRIVATE.invalid")
    data=b'\xef\xbb\xbfregistry=${PRIVATE}\n//PRIVATE.invalid/:_authToken=PRIVATE\n'
    path,report=native(tmp_path,monkeypatch,data,"npmrc-text")
    assert report["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert not report["findings"] and "PRIVATE" not in json.dumps(report)
    assert path.read_bytes() == data
    _,report=native(tmp_path,monkeypatch,lock(hasInstallScript=True))
    assert keys(report) == ["install-script-declaration"]


def test_cli_template_catalog_coverage_sarif_and_nonoverwrite(tmp_path,monkeypatch,capsys):
    from hunterqa.coverage_audit import coverage_audit,render_checklist
    from hunterqa.sarif_export import export_sarif
    path=tmp_path/"evidence.json"
    path.write_bytes(Path("templates/HunterQA-supply-chain-review-template.json").read_bytes())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    out=tmp_path/"report.json"
    main(["supply-chain-review","--input",str(path),"--out",str(out),"--authorized"])
    assert json.loads(out.read_text())["status"] == "insufficient-evidence"
    with pytest.raises(FileExistsError):
        main(["supply-chain-review","--input",str(path),"--out",str(out),"--authorized"])
    main(["supply-chain-review-catalog"])
    output=capsys.readouterr().out
    assert all("offensive-"+k in output for k in PROFILES)
    assert Path("docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()
    assert not coverage_audit()["all_seven_areas_complete"]
    assert any(p["name"] == "Supply Chain" for p in coverage_audit()["category_packs"])
    data=lock(integrity=None)
    data["packages"]["node_modules/SECOND"]=dict(data["packages"]["node_modules/PRIVATE"])
    path,_=native(tmp_path,monkeypatch,data)
    out=tmp_path/"lock-report.json"
    main(["supply-chain-config-review","--mode","npm-lock-json","--input",str(path),"--out",str(out),"--authorized"])
    results=export_sarif(out)["runs"][0]["results"]
    assert len(results) == 2 and all("locations" not in r for r in results)
    assert results[0]["partialFingerprints"] != results[1]["partialFingerprints"]


def test_authorization_roots_symlinks_and_mode(tmp_path,monkeypatch):
    with pytest.raises(PermissionError):
        review_file(tmp_path/"absent")
    allowed=tmp_path/"allowed"
    allowed.mkdir()
    path,_=native(allowed,monkeypatch,lock())
    with pytest.raises(ValueError):
        main(["supply-chain-config-review","--mode","npm-lock-json","--input",str(path),"--out",str(tmp_path/"outside.json"),"--authorized"])
    assert not (tmp_path/"outside.json").exists()
    link=allowed/"link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        review_file(link,authorized=True)
    with pytest.raises(ValueError):
        review_file(path,authorized=True,mode="install")
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
    entry={"resolved":"http://PRIVATE:PRIVATE@PRIVATE.invalid/x","hasInstallScript":True}
    _,report=native(tmp_path,monkeypatch,{"lockfileVersion":2,"packages":{str(i):entry for i in range(1500)}})
    assert len(report["findings"]) == 500 and report["truncated"] and report["candidates_not_retained"] == 5500
    with pytest.raises(ValueError):
        native(tmp_path,monkeypatch,{"lockfileVersion":2,"packages":{str(i):entry for i in range(1501)}})
