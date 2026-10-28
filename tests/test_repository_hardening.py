import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from hunterqa.agent_adapter import ExistingAgentReportAdapter
from hunterqa.engines.dependencies import inventory, match_local_advisories
from hunterqa.engines.sarif import import_sarif
from hunterqa.orchestrator import normalize_semgrep
from hunterqa.source_files import project_files, read_bounded
from tools.verify_release_archive import verify_archive
from .conftest import csrf


@pytest.mark.parametrize("host", ["attacker.example", "127.0.0.1.attacker.example", "localhost.attacker.example"])
def test_dashboard_rejects_untrusted_host_even_from_loopback(client, host):
    assert client.get("/", headers={"Host": host}).status_code == 400


def test_dashboard_rejects_remote_peer_and_ignores_forwarded_header(client):
    assert client.get("/", environ_overrides={"REMOTE_ADDR": "192.0.2.1"},
                      headers={"X-Forwarded-For": "127.0.0.1", "Host": "localhost"}).status_code == 403


def test_dashboard_csp_nonce_allows_only_its_inline_polling_script(client):
    first, second = client.get("/research"), client.get("/research")
    policy = first.headers["Content-Security-Policy"]
    nonce = policy.split("'nonce-", 1)[1].split("'", 1)[0]
    assert f'nonce="{nonce}"'.encode() in first.data
    assert nonce not in second.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in policy
    assert "script-src 'self' 'nonce-" in policy


def test_malformed_unicode_csrf_is_rejected_without_server_error(client, approved_root):
    csrf(client)
    response = client.post("/projects", data={"csrf_token": "غيرصالح", "name": "test", "path": str(approved_root)})
    assert response.status_code == 400


@pytest.mark.parametrize("value", [None, [], "invalid", True, -5, 0, {"line": 1}])
def test_malformed_analyzer_locations_remain_unverified(tmp_path, value):
    sarif = tmp_path / "scan.sarif"
    sarif.write_text(json.dumps({"runs": [{"results": [{"level": "error", "message": [],
        "locations": [{"physicalLocation": {"artifactLocation": [], "region": {"startLine": value}}}]}]}]}))
    row = import_sarif(sarif)[0]
    assert row["line_start"] == 1
    assert row["severity"] == "ERROR"
    assert row["verification_status"] == "unverified"
    agent = tmp_path / "agent.json"
    agent.write_text(json.dumps([{"line_start": value, "line_end": value}]))
    assert ExistingAgentReportAdapter().load(agent)[0]["line_start"] == 1
    item = normalize_semgrep({"path": "src/main.py", "start": value, "end": value}, tmp_path)
    assert item["file_path"] == str(Path("src/main.py"))
    assert item["line_start"] == 1


def test_bad_sarif_results_collection_is_skipped(tmp_path):
    file = tmp_path / "scan.sarif"
    file.write_text(json.dumps({"runs": [{"results": None}, {"results": "invalid"}]}))
    assert import_sarif(file) == []


def test_inventory_normalizes_pypi_names_and_does_not_match_constraints(tmp_path):
    (tmp_path / "requirements.txt").write_text("Demo.Pkg__Name==1.2.3\n")
    assert inventory(tmp_path)[0]["name"] == "demo-pkg-name"
    pkg = {"ecosystem": "npm", "name": "example", "version": "1.2.3", "source": "package.json",
           "resolution": "unresolved_manifest_constraint"}
    assert match_local_advisories([pkg], [{"ecosystem": "npm", "package": "example", "version": "1.2.3"}]) == []


def test_project_enumeration_prunes_dependencies_and_is_bounded(tmp_path):
    ignored = tmp_path / "node_modules" / "large"
    ignored.mkdir(parents=True)
    (ignored / "requirements.txt").write_text("not scanned")
    (tmp_path / "source.py").write_text("safe")
    assert [p.name for p in project_files(tmp_path)] == ["source.py"]
    with pytest.raises(ValueError, match="enumeration limit"):
        list(project_files(tmp_path, max_entries=1))
    with pytest.raises(ValueError, match="size limit"):
        read_bounded(tmp_path / "source.py", 2)


@pytest.mark.parametrize("member", ["HunterQA-AI/a//b", "HunterQA-AI/./x", "HunterQA-AI/C:/x", "HunterQA-AI/../x"])
def test_archive_noncanonical_paths_rejected(tmp_path, member):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr(member, "contents")
    with pytest.raises(ValueError, match="Unsafe"):
        verify_archive(archive)


def test_archive_symlink_members_rejected(tmp_path):
    archive = tmp_path / "bad.zip"
    member = zipfile.ZipInfo("HunterQA-AI/link")
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr(member, "../../private")
    with pytest.raises(ValueError, match="Unsafe"):
        verify_archive(archive)


def test_campaign_history_accepts_platform_path_separator(tmp_path):
    from hunterqa.engines.campaign_history import _root
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir()
    two.mkdir()
    assert _root(two, str(one) + os.pathsep + str(two)) == two.resolve()


def test_openapi_anonymous_alternative_is_not_invalid_authentication():
    from hunterqa.api_surface_v12 import _auth_declaration
    assert _auth_declaration({"security": [{}, {"apiKey": []}]}, None) == "optional_authentication"
    assert _auth_declaration({"security": [{}]}, None) == "explicitly_public"
    assert _auth_declaration({"security": [{"apiKey": "invalid"}]}, None) == "invalid"


@pytest.mark.skipif(os.name != "posix", reason="Actual executable replay is POSIX-only")
def test_crash_replay_creates_private_output_and_refuses_overwrite(tmp_path, monkeypatch):
    from hunterqa.engines import fuzzing
    binary = tmp_path / "fixture"
    binary.write_text("#!/bin/sh\nexit 1\n")
    binary.chmod(0o700)
    crashes = tmp_path / "crashes"
    crashes.mkdir()
    (crashes / "id:000000").write_bytes(b"fixture")
    output = tmp_path / "replay.json"
    report = fuzzing.verify_crashes(approved_lab=tmp_path, binary_path=binary, crash_dir=crashes,
                                   output=output, authorized=True, max_crashes=1)
    assert report["total_crashes"] == 1
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    monkeypatch.setattr(fuzzing, "_replay", lambda *a: pytest.fail("Replayed despite an existing output"))
    with pytest.raises(ValueError, match="new crash replay"):
        fuzzing.verify_crashes(approved_lab=tmp_path, binary_path=binary, crash_dir=crashes,
                              output=output, authorized=True)
