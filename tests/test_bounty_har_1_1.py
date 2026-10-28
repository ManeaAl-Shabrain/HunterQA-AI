import json
import pytest

from hunterqa.bounty import import_har, bounty_markdown, read_bounty_report


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({
        "program": "Authorized Example",
        "platform": "private",
        "authorization_reference": "Example written approval number 123",
        "acknowledged_authorization": True,
        "allowed_hosts": ["example.test"],
        "methods": ["HEAD"],
    }))
    har = tmp_path / "input.har"
    return profile, har


def test_har_import_has_no_replay_or_secret_leak(files):
    profile, har = files
    har.write_text(json.dumps({"log": {"entries": [{
        "request": {"url": "https://example.test/page?token=privatevalue",
                    "method": "GET", "headers": [{"name": "Authorization", "value": "Bearer secret"}]},
        "response": {"status": 200, "headers": [
            {"name": "Set-Cookie", "value": "session=supersecret; Path=/"},
            {"name": "Content-Type", "value": "text/html"},
        ], "content": {"text": "sensitive html body"}},
    }]}}))
    report = import_har(profile, har, authorized=True)
    payload = json.dumps(report)
    for token in ("privatevalue", "supersecret", "sensitive html body", "Bearer secret"):
        assert token not in payload
    assert report["mode"] == "offline_har_import"
    assert report["observations"][0]["url"] == "https://example.test/page"
    assert report["claims"]["confirmed_zero_days"] == 0


def test_har_out_of_scope_skipped(files):
    profile, har = files
    har.write_text(json.dumps({"log": {"entries": [
        {"request": {"url": "https://evil.test/", "method": "HEAD"},
         "response": {"status": 200, "headers": []}}
    ]}}))
    result = import_har(profile, har, authorized=True)
    assert result["observations"] == []
    assert result["skipped_out_of_scope_or_invalid"] == 1


def test_invalid_har_does_not_crash(files):
    profile, har = files
    har.write_text(json.dumps({"log": []}))
    with pytest.raises(ValueError):
        import_har(profile, har, authorized=True)


def test_import_needs_authorization(files):
    profile, har = files
    har.write_text(json.dumps({"log": {"entries": []}}))
    with pytest.raises(PermissionError):
        import_har(profile, har)


def test_draft_does_not_claim_confirmed_vulnerability():
    report = {
        "engine": "hunterqa_authorized_bounty_observation",
        "program": "My Authorized App",
        "findings": [{"title": "CSP not observed",
                      "source_url": "https://example.test/"}],
    }
    result = bounty_markdown(report)
    assert "Manual" not in result or "Unverified" in result
    assert "Impact: Not established" in result
    assert "CWE / CVE: Not assigned" in result
    assert "My Authorized App" in result


def test_read_only_report_rejects_malformed_files(files):
    profile, har = files
    har.write_text(json.dumps({"engine": "untrusted", "observations": [], "findings": []}))
    assert read_bounty_report(har)["status"] == "unavailable"
