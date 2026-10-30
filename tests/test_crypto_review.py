"""Owned synthetic declarations/source; never execute reviewed source or negotiate TLS."""
import copy
import hashlib
import json
import socket
import subprocess
import traceback
from pathlib import Path

import pytest

from hunterqa.cli import main
from hunterqa.crypto_review import MAX_BYTES, PROFILES, review_evidence, review_file


def evidence(key="crypto-attacks", value=None):
    return {"schema_version":1,"records":[{"id":"owned-one","skill":"offensive-"+key,"observations":dict.fromkeys(PROFILES[key],value)}]}


def source(tmp_path, monkeypatch, text):
    path=tmp_path/"source.py"
    path.write_bytes(text if isinstance(text,bytes) else text.encode())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    return path,review_file(path,authorized=True,mode="python-source")


def keys(report):
    return [f["rule_id"].removeprefix("crypto-review.") for f in report["findings"]]


@pytest.mark.parametrize("key,field", [(k,f) for k,fs in PROFILES.items() for f in fs])
def test_contract_positive_negative_unknown(key,field):
    data=evidence(key,True)
    assert not review_evidence(data)["findings"]
    data["records"][0]["observations"][field]=False
    assert len(review_evidence(data)["findings"]) == 1
    report=review_evidence(evidence(key))
    assert report["status"] == "insufficient-evidence"
    assert report["network_requests"] == report["external_tools_executed"] == report["referenced_files_opened"] == 0
    assert not report["cryptographic_correctness_verified"] and not report["runtime_tls_verified"]
    assert not report["all_skills_automated"] and report["real_world_effectiveness"] == "unverified"


@pytest.mark.parametrize("change", [lambda d:d.update(schema_version=True),lambda d:d.update(schema_version=2),
    lambda d:d.update(records=[]),lambda d:d.update(extra="PRIVATE"),lambda d:d["records"][0].update(id="PRIVATE BAD"),
    lambda d:d["records"][0].update(skill=[]),lambda d:d["records"][0].update(observations={}),
    lambda d:d["records"][0]["observations"].update(algorithm_usage_reviewed=1),
    lambda d:d["records"].append(copy.deepcopy(d["records"][0]))])
def test_contract_schema(change):
    data=evidence()
    change(data)
    with pytest.raises(ValueError,match="withheld"):
        review_evidence(data)


@pytest.mark.parametrize("text,expected", [
    ("import hashlib\nhashlib.md5(b'PRIVATE')",["weak-hash"]),
    ("import hashlib as h\nh.sha1(b'PRIVATE')",["weak-hash"]),
    ("from hashlib import md5 as digest\ndigest(b'PRIVATE')",["weak-hash"]),
    ("import hashlib\nhashlib.new('SHA-1',b'PRIVATE')",["weak-hash"]),
    ("import hashlib\nhashlib.sha256(b'PRIVATE')",[]),
    ("import hashlib\nhashlib.new(variable,b'PRIVATE')",[]),
    ("import random\nrandom.getrandbits(128)",["general-random"]),
    ("from random import choice\nchoice('PRIVATE')",["general-random"]),
    ("import secrets\nsecrets.token_bytes(32)",[]),
    ("from Crypto.Cipher import AES\nAES.new(b'PRIVATE', AES.MODE_ECB)",["ecb-mode"]),
    ("import Cryptodome.Cipher.AES as a\na.new(b'PRIVATE',mode=a.MODE_ECB)",["ecb-mode"]),
    ("from Crypto.Cipher.AES import new, MODE_ECB\nnew(b'PRIVATE', MODE_ECB)",["ecb-mode"]),
    ("from Crypto.Cipher import AES\nAES.new(b'PRIVATE', AES.MODE_GCM)",[]),
    ("import ssl\nssl._create_unverified_context()",["unverified-context"]),
    ("from ssl import _create_unverified_context as ctx\nctx()",["unverified-context"]),
    ("import ssl\nssl.create_default_context()",[]),
    ("import ssl\nssl.SSLContext(ssl.PROTOCOL_TLSv1_1)",["legacy-protocol"]),
    ("import ssl as s\ns.SSLContext(protocol=s.PROTOCOL_SSLv3)",["legacy-protocol"]),
    ("import ssl\nssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)",[]),
    ("import requests\nrequests.get('PRIVATE',verify=False)",["verify-disabled"]),
    ("from httpx import AsyncClient as C\nC(verify=False)",["verify-disabled"]),
    ("import requests\nrequests.get('PRIVATE',verify=True)",[]),
    ("import requests\nrequests.get('PRIVATE',verify=0)",[]),
    ("import httpx\nhttpx.get('PRIVATE',verify=flag)",[]),
    ("text='hashlib.md5(PRIVATE)'\n# ssl._create_unverified_context()",[]),
])
def test_selected_source_patterns(tmp_path,monkeypatch,text,expected):
    _,report=source(tmp_path,monkeypatch,text)
    assert keys(report) == expected
    assert all(f["severity"] == "INFO" and f["verification_status"] == "unverified" for f in report["findings"])
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("text", [
    "import hashlib\nhashlib=other\nhashlib.md5(b'PRIVATE')",
    "import hashlib\ndef f(hashlib):\n return hashlib.md5(b'PRIVATE')",
    "import hashlib\ndef hashlib(): pass\nhashlib.md5(b'PRIVATE')",
    "import hashlib\nclass hashlib: pass\nhashlib.md5(b'PRIVATE')",
    "import hashlib\nimport other as hashlib\nhashlib.md5(b'PRIVATE')",
    "import hashlib\nfrom other import *\nhashlib.md5(b'PRIVATE')",
    "def f():\n import hashlib\n return hashlib.md5(b'PRIVATE')",
    "from . import hashlib\nhashlib.md5(b'PRIVATE')",
    "import hashlib\ndel hashlib\nhashlib.md5(b'PRIVATE')",
    "import hashlib\nmatch value:\n case {'x':hashlib}: pass\nhashlib.md5(b'PRIVATE')",
    "import hashlib\ntry: pass\nexcept Exception as hashlib: pass\nhashlib.md5(b'PRIVATE')",
    "hashlib.md5(b'PRIVATE')",
])
def test_ambiguous_names_are_skipped(tmp_path,monkeypatch,text):
    _,report=source(tmp_path,monkeypatch,text)
    assert not report["findings"]
    assert not report["source_review"]["complete_source_analysis"]


@pytest.mark.parametrize("raw", [b'def PRIVATE(',b'\xff',b'\x00PRIVATE',b' '* (MAX_BYTES+1),
    b'x='+b'('*250+b'0'+b')'*250])
def test_source_parse_bounds_and_error_privacy(tmp_path,monkeypatch,raw):
    with pytest.raises(ValueError) as exc:
        source(tmp_path,monkeypatch,raw)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("raw", [b'{"records":[],"records":[]}',b'{"private":NaN}',b'{"private":1e9999}',
    b'PRIVATE',b'\xff',b'['*45+b'0'+b']'*45])
def test_strict_json(tmp_path,monkeypatch,raw):
    path=tmp_path/"evidence.json"
    path.write_bytes(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    with pytest.raises(ValueError) as exc:
        review_file(path,authorized=True)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_no_network_process_import_execution_or_source_leak(tmp_path,monkeypatch):
    def deny(*args,**kwargs):
        pytest.fail("Offline source reviewer attempted process or network execution")
    monkeypatch.setattr(socket,"socket",deny)
    monkeypatch.setattr(socket,"getaddrinfo",deny)
    monkeypatch.setattr(subprocess,"Popen",deny)
    text="import hashlib\nimport nonexistent_PRIVATE\nraise RuntimeError('PRIVATE')\nhashlib.md5(b'PRIVATE')"
    path,report=source(tmp_path,monkeypatch,text)
    assert keys(report) == ["weak-hash"]
    assert report["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert "PRIVATE" not in json.dumps(report)


def test_output_template_catalog_coverage_and_sarif(tmp_path,monkeypatch,capsys):
    from hunterqa.coverage_audit import coverage_audit,render_checklist
    from hunterqa.sarif_export import export_sarif
    path=tmp_path/"evidence.json"
    path.write_bytes(Path("templates/HunterQA-crypto-review-template.json").read_bytes())
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    out=tmp_path/"report.json"
    main(["crypto-review","--input",str(path),"--out",str(out),"--authorized"])
    assert json.loads(out.read_text())["status"] == "insufficient-evidence"
    with pytest.raises(FileExistsError):
        main(["crypto-review","--input",str(path),"--out",str(out),"--authorized"])
    main(["crypto-review-catalog"])
    assert "offensive-tls-attacks" in capsys.readouterr().out
    assert Path("docs/FEATURE_READINESS_CHECKLIST.md").read_text(encoding="utf-8") == render_checklist()
    assert not coverage_audit()["all_seven_areas_complete"]
    assert any(p["name"] == "Cryptography" for p in coverage_audit()["category_packs"])
    path,_=source(tmp_path,monkeypatch,"import hashlib\nhashlib.md5(b'PRIVATE'); hashlib.md5(b'PRIVATE')")
    report=tmp_path/"source-report.json"
    main(["crypto-source-review","--input",str(path),"--out",str(report),"--authorized"])
    results=export_sarif(report)["runs"][0]["results"]
    assert len(results) == 2 and all("locations" not in r for r in results)
    assert results[0]["partialFingerprints"] != results[1]["partialFingerprints"]


def test_authorization_roots_symlinks_and_mode(tmp_path,monkeypatch):
    with pytest.raises(PermissionError):
        review_file(tmp_path/"absent")
    path,_=source(tmp_path,monkeypatch,"pass")
    other=tmp_path/"other"
    other.mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(other))
    with pytest.raises(ValueError):
        review_file(path,authorized=True)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS",str(tmp_path))
    link=tmp_path/"link.py"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        review_file(link,authorized=True)
    with pytest.raises(ValueError):
        review_file(path,authorized=True,mode="live")


def test_record_and_finding_limits(tmp_path,monkeypatch):
    data={"schema_version":1,"records":[{"id":k+str(i),"skill":"offensive-"+k,"observations":dict.fromkeys(fs,None)} for k,fs in PROFILES.items() for i in range(10)]}
    assert len(review_evidence(data)["records"]) == 20
    data["records"].append({**data["records"][0],"id":"extra"})
    with pytest.raises(ValueError):
        review_evidence(data)
    _,report=source(tmp_path,monkeypatch,"import hashlib\n"+"hashlib.md5(b'PRIVATE')\n"*505)
    assert len(report["findings"]) == 500 and report["truncated"]
    assert report["candidates_not_retained"] == 5
    with pytest.raises(ValueError):
        source(tmp_path,monkeypatch,"x=["+"0,"*51000+"]")


def test_parser_warnings_withhold_source(tmp_path,monkeypatch):
    import warnings
    from hunterqa.crypto_review import catalog
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _,report=source(tmp_path,monkeypatch,"value='\\qPRIVATE'")
    assert not caught and "PRIVATE" not in json.dumps(report)
    assert all(row["native_source_modes"] == ["python-source"] for row in catalog())
