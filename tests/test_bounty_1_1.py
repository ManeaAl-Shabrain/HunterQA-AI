"""HunterQA 1.1 authorization, safe HTTP egress and reporting regression tests.

No test makes a real network request.
"""
import json

import pytest

from hunterqa.bounty import (
    BountyPolicy, _approved_file, assess, inspect_headers, read_bounty_report,
    resolve_pinned,
)


@pytest.fixture
def profile():
    return {
        "program": "Authorized lab",
        "platform": "local-lab",
        "authorization_reference": "Lab permission record #1",
        "acknowledged_authorization": True,
        "allowed_hosts": ["app.example.test"],
        "excluded_hosts": ["admin.example.test"],
        "allowed_paths": ["/"],
        "excluded_paths": ["/admin"],
        "methods": ["HEAD"],
        "allowed_ports": [443],
        "max_requests": 3,
        "interval_seconds": 0.5,
    }


def test_explicit_policy_and_authorization_required(profile):
    assert BountyPolicy.from_dict(profile).program == "Authorized lab"
    profile.pop("acknowledged_authorization")
    with pytest.raises(ValueError, match="authorization"):
        BountyPolicy.from_dict(profile)


def test_wildcard_hosts_never_implicitly_authorized(profile):
    profile["allowed_hosts"] = ["*.example.test"]
    with pytest.raises(ValueError):
        BountyPolicy.from_dict(profile)


@pytest.mark.parametrize("url", [
    "https://app.example.test.evil.com/",
    "https://attacker@app.example.test/",
    "https://app.example.test/admin",
    "https://app.example.test/admin/child",
    "https://app.example.test/%2e%2e/admin",
    "https://app.example.test/?token=abc",
    "https://app.example.test:4443/",
    "http://app.example.test/",
    "file:///etc/passwd",
    "https://app.example.test//admin",
])
def test_scope_denied(profile, url):
    with pytest.raises(ValueError):
        BountyPolicy.from_dict(profile).authorize_url(url)


def test_get_not_automatically_authorized(profile):
    with pytest.raises(ValueError):
        BountyPolicy.from_dict(profile).authorize_url("https://app.example.test/", "GET")


def test_lab_private_requires_explicit_lab_mode(profile):
    profile["allow_private_network"] = True
    with pytest.raises(ValueError):
        BountyPolicy.from_dict(profile)
    profile["lab_mode"] = True
    profile["allow_http"] = True
    profile["allowed_hosts"] = ["127.0.0.1"]
    profile["allowed_ports"] = [5000]
    parts, host, port, _ = BountyPolicy.from_dict(profile).authorize_url(
        "http://127.0.0.1:5000/"
    )
    assert (parts.scheme, host, port) == ("http", "127.0.0.1", 5000)


def test_dns_private_answer_rejected_before_connect(profile, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(ValueError, match="Unsafe DNS"):
        resolve_pinned(BountyPolicy.from_dict(profile), "app.example.test", 443)


def test_mixed_public_private_dns_answer_rejected(profile, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (2, 1, 6, "", ("8.8.8.8", 443)),
        (2, 1, 6, "", ("169.254.169.254", 443)),
    ])
    with pytest.raises(ValueError, match="Unsafe DNS"):
        resolve_pinned(BountyPolicy.from_dict(profile), "app.example.test", 443)


def test_out_of_scope_list_aborts_before_any_requests(profile, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    p = tmp_path / "program.json"
    p.write_text(json.dumps(profile))
    targets = tmp_path / "targets.txt"
    targets.write_text("https://app.example.test/\nhttps://evil.example.org/\n")
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError("Transport must never be called")
    with pytest.raises(ValueError, match="outside exact"):
        assess(p, targets, authorized=True, transport=forbidden)
    assert calls == []


def test_run_requires_explicit_flag(profile, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    p = tmp_path / "program.json"
    p.write_text(json.dumps(profile))
    targets = tmp_path / "targets.txt"
    targets.write_text("https://app.example.test/")
    with pytest.raises(PermissionError):
        assess(p, targets)


def test_cookie_values_not_saved_and_findings_unverified(profile, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    p = tmp_path / "program.json"
    p.write_text(json.dumps(profile))
    targets = tmp_path / "targets.txt"
    targets.write_text("https://app.example.test/")
    def fake_transport(policy, url, method):
        return {
            "url": url, "method": method, "status": 200,
            "headers": [("Set-Cookie", "session=top-secret; Path=/"),
                        ("Server", "internal-server"),
                        ("Content-Type", "text/html")],
            "body_sha256": None, "body_truncated": False,
        }
    report = assess(p, targets, authorized=True, transport=fake_transport)
    assert "top-secret" not in json.dumps(report)
    assert "internal-server" not in json.dumps(report)
    assert report["findings"]
    assert all(x["confirmed"] is False for x in report["findings"])
    assert report["claims"]["confirmed_zero_days"] == 0


def test_429_stops_campaign(profile, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(profile))
    targets = tmp_path / "targets.txt"
    targets.write_text("https://app.example.test/one\nhttps://app.example.test/two\n")
    seen = []
    def fake_transport(policy, url, method):
        seen.append(url)
        return {"url": url, "method": method, "status": 429, "headers": []}
    result = assess(p, targets, authorized=True, transport=fake_transport,
                    sleeper=lambda _: None)
    assert len(result["observations"]) == 1
    assert len(seen) == 1


def test_symlink_evidence_rejected(profile, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    p = tmp_path / "real.json"
    p.write_text(json.dumps(profile))
    link = tmp_path / "link.json"
    link.symlink_to(p)
    with pytest.raises(ValueError, match="Symlink"):
        _approved_file(link)


def test_read_only_report_and_no_page_trigger(client, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    response = client.get("/bounty?url=https://evil.example.com")
    assert response.status_code == 200
    assert b"Bug Bounty" in response.data
    raw = {
        "engine": "hunterqa_authorized_bounty_observation",
        "program": "Lab project",
        "observations": [{"status": 200, "url": "https://app.example.test/", "method": "HEAD"}],
        "findings": [{"id": "header.hsts.absent", "title": "HSTS not observed",
                      "source_url": "https://app.example.test/"}],
    }
    p = tmp_path / "report.json"
    p.write_text(json.dumps(raw))
    report = read_bounty_report(p)
    assert report["status"] == "ready"
    assert report["findings"][0]["verification"] == "manual_review_required"


def test_header_analysis_is_not_exploit_confirmation():
    findings = inspect_headers({
        "url": "https://app.example.test/",
        "method": "HEAD",
        "status": 200,
        "headers": [],
    })
    assert findings
    assert all(f["cve_id"] is None and f["zero_day_confirmed"] is False for f in findings)
