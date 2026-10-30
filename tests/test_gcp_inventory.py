"""Owned/synthetic GCP contracts; never contact real Google Cloud projects."""
import hashlib
import json
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from hunterqa import gcp_inventory as gcp
from hunterqa.cli import main
from hunterqa.engagement import utcnow

PROJECT = "owned-fixture-123"
NUMBER = "123456789012"
PARENT = "folders/123456789"
TOKEN = "synthetic-private-gcp-bearer-0123456789"
SNAPSHOT = (utcnow() - timedelta(seconds=2)).replace(microsecond=123456).isoformat(timespec="microseconds").replace("+00:00", "Z")


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    data = {"schema_version": 1, "provider": "gcp", "project_id": PROJECT, "project_number": NUMBER,
        "expected_parent": PARENT, "read_time": SNAPSHOT, "authorization_reference": "Written private project inventory grant",
        "acknowledged_authorization": True, "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(),
        "max_pages": 2, "page_size": 2, "max_resources": 4, "interval_seconds": 0.5}
    keys = {"access_token": TOKEN, "expires_at": (utcnow() + timedelta(minutes=15)).isoformat()}
    source, secret = tmp_path / "gcp-contract.json", tmp_path / "gcp-token.json"
    def save(**changes):
        data.update(changes)
        source.write_text(json.dumps(data), encoding="utf-8")
        secret.write_text(json.dumps(keys), encoding="utf-8")
    save()
    return source, secret, data, keys, save


def context(**changes):
    return {"name": "projects/" + NUMBER, "projectId": PROJECT, "parent": PARENT, "state": "ACTIVE",
            "displayName": "Private project display", "labels": {"secret": "private-label"}, **changes}


def asset(instance="PrivateInstance", **changes):
    return {"name": f"//compute.googleapis.com/projects/{PROJECT}/zones/private-zone/instances/{instance}",
            "assetType": "compute.googleapis.com/Instance", "ancestors": ["projects/" + NUMBER, PARENT, "organizations/987654321"],
            "resource": {"data": {"private-config": "not-retained"}, "resourceUrl": "https://evil.invalid/never-follow"}, **changes}


def stamp():
    return SNAPSHOT


def page(values=None, **changes):
    return {"readTime": stamp(), "assets": values if values is not None else [asset()], **changes}


def response(data, status=200):
    return {"status": status, "body": json.dumps(data).encode()}


def run(files, responses, *, after=None):
    calls = []
    def transport(target, token, *, before_send):
        before_send()
        assert token == TOKEN
        assert urlsplit(target).netloc in (gcp.CONTEXT_HOST, gcp.ASSET_HOST)
        calls.append(target)
        result = responses[len(calls) - 1]
        if after:
            after(len(calls))
        return result
    result = gcp.inventory(files[0], files[1], authorized=True, transport=transport, sleeper=lambda _: None)
    return result, calls


def test_context_then_snapshot_pinned_pages_deduplicate_and_preserve_case(files):
    snapshot = stamp()
    report, calls = run(files, [response(context()), response(page(readTime=snapshot, nextPageToken="private-page-token")),
        response(page([asset(), asset("privateinstance")], readTime=snapshot))])
    assert len(calls) == report["requests_attempted"] == report["requests_completed"] == 3
    assert urlsplit(calls[0]).path == "/v3/projects/" + NUMBER
    assert parse_qs(urlsplit(calls[0]).query) == {"fields": ["name,projectId,parent,state"]}
    initial, subsequent = (parse_qs(urlsplit(c).query) for c in calls[1:])
    assert initial == {"contentType": ["RESOURCE"], "pageSize": ["2"], "fields": [gcp.PROJECTION], "readTime": [snapshot]}
    assert subsequent["readTime"] == [snapshot] and subsequent["pageToken"] == ["private-page-token"]
    assert report["project_context_matched"] and report["visible_pagination_exhausted"]
    assert report["read_time_consistent"] is True and report["snapshot_read_time"] == snapshot
    assert report["assets_retained"] == 2 and report["duplicates_not_retained"] == 1
    assert report["assets"][0]["asset_ref"] != report["assets"][1]["asset_ref"]
    assert not report["inventory_complete"] and not report["effective_permissions_verified"] and not report["owner_grant_verified"]
    text = json.dumps(report)
    for private in (PROJECT, NUMBER, PARENT, TOKEN, "PrivateInstance", "private-zone", "private-page-token", "not-retained", "evil.invalid", "private-label", str(files[1])):
        assert private not in text
    assert report["findings"] == []


@pytest.mark.parametrize("changes", [{"name": "projects/999999999999"}, {"projectId": "other-project"},
    {"parent": "folders/999"}, {"parent": None}, {"state": "DELETE_REQUESTED"}])
def test_context_mismatch_prevents_asset_api_call(files, changes):
    report, calls = run(files, [response(context(**changes))])
    assert len(calls) == 1 and report["outcome"] == "project-context-mismatch"
    assert not report["project_context_matched"] and report["assets"] == []


def test_parentless_project_and_bucket_ancestry_binding(files):
    files[4](expected_parent=None)
    row = asset(name="//storage.googleapis.com/buckets/private-bucket", assetType="storage.googleapis.com/Bucket", ancestors=["projects/" + NUMBER])
    report, _ = run(files, [response(context(parent=None)), response(page([row]))])
    assert report["assets_retained"] == 1 and report["assets"][0]["kind"] == "storage-bucket"


@pytest.mark.parametrize("changes", [{"ancestors": []}, {"ancestors": ["projects/999", PARENT]},
    {"ancestors": ["projects/" + NUMBER, "folders/999"]},
    {"ancestors": ["projects/" + NUMBER, PARENT, PARENT]},
    {"ancestors": ["projects/" + NUMBER, PARENT, "organizations/987", "folders/654"]},
    {"name": "//compute.googleapis.com/projects/other-project/zones/x/instances/y"},
    {"name": "https://evil.invalid/secret"}, {"name": "//compute.googleapis.com/projects/../secret"},
    {"name": "//compute.googleapis.com/projects/" + PROJECT + "/instances/x%2fy"},
    {"assetType": "private.invalid/Type"}, {"assetType": None}])
def test_cross_project_ambiguous_or_unsupported_asset_invalidates_whole_page(files, changes):
    report, calls = run(files, [response(context()), response(page([asset(), asset(**changes)]))])
    assert len(calls) == 2 and report["outcome"] == "invalid-response" and report["assets_retained"] == 0


def test_snapshot_mismatch_detects_nanosecond_difference_before_second_page_retention(files):
    first = stamp()[:-1] + "001Z"
    second = first[:-4] + "002Z"
    files[4](read_time=first)
    assert gcp._expiry(first) == gcp._expiry(second)  # datetime precision cannot distinguish these alone.
    report, _ = run(files, [response(context()), response(page(readTime=first, nextPageToken="next")),
        response(page([asset("new-instance")], readTime=second))])
    assert report["outcome"] == "snapshot-mismatch" and report["read_time_consistent"] is False
    assert report["assets_retained"] == 1 and report["pages_observed"] == 1


def test_equivalent_snapshot_precision_is_compared_without_losing_nanoseconds(files):
    report, _ = run(files, [response(context()), response(page(readTime=stamp()[:-1] + "000Z"))])
    assert report["visible_pagination_exhausted"] and report["read_time_consistent"] is True
    assert report["snapshot_read_time"] == stamp()


@pytest.mark.parametrize("value", [None, "not-a-time", "2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z", "2026-10-31T00:00:00+00:00"])
def test_invalid_or_stale_read_time_does_not_commit_page(files, value):
    report, _ = run(files, [response(context()), response(page(readTime=value))])
    assert report["outcome"] == "invalid-response" and report["assets"] == []


@pytest.mark.parametrize("token", [None, [], 7, "x" * 2049, "private\r\nheader"])
def test_invalid_page_token_does_not_trigger_another_request(files, token):
    report, calls = run(files, [response(context()), response(page(nextPageToken=token))])
    assert len(calls) == 2 and report["outcome"] == "page-token-rejected" and report["assets_retained"] == 1


def test_url_shaped_page_token_is_only_encoded_data_on_fixed_host(files):
    snapshot, opaque = stamp(), "https://evil.invalid/private?x=y&project=other"
    report, calls = run(files, [response(context()), response(page(readTime=snapshot, nextPageToken=opaque)),
        response(page([], readTime=snapshot))])
    assert urlsplit(calls[2]).netloc == gcp.ASSET_HOST
    assert parse_qs(urlsplit(calls[2]).query)["pageToken"] == [opaque]
    assert report["outcome"] == "visible-pages-exhausted" and opaque not in json.dumps(report)


def test_pagination_loop_is_not_requested_twice(files):
    files[4](max_pages=5)
    snapshot = stamp()
    report, calls = run(files, [response(context()), response(page(readTime=snapshot, nextPageToken="same")),
        response(page([], readTime=snapshot, nextPageToken="same"))])
    assert len(calls) == 3 and report["outcome"] == "pagination-loop"


@pytest.mark.parametrize("field,value,outcome", [("max_pages", 1, "page-limit"), ("max_resources", 1, "resource-limit")])
def test_request_and_resource_limits_remain_partial(files, field, value, outcome):
    files[4](**{field: value})
    report, calls = run(files, [response(context()), response(page([asset(), asset("other")], nextPageToken="next"))])
    assert len(calls) == 2 and report["outcome"] == outcome and not report["visible_pagination_exhausted"]


@pytest.mark.parametrize("status", [301, 302, 401, 403, 429, 500])
def test_error_redirect_throttle_no_retry(files, status):
    report, calls = run(files, [response(context()), response({"error": {"message": TOKEN}}, status)])
    assert len(calls) == 2 and report["outcome"] == "http-error" and TOKEN not in json.dumps(report)


@pytest.mark.parametrize("field,value", [("schema_version", True), ("provider", "azure"), ("project_id", "short"),
    ("project_id", "Upper-project"), ("project_id", "owned-project-"), ("project_number", "0123"),
    ("project_number", "*"), ("project_number", 123), ("expected_parent", "projects/123"),
    ("max_pages", 6), ("page_size", 101), ("max_resources", 501), ("interval_seconds", float("nan")),
    ("interval_seconds", True), ("acknowledged_authorization", 1), ("expires_at", "2020-01-01T00:00:00Z"),
    ("read_time", None), ("read_time", "2020-01-01T00:00:00Z"), ("read_time", "2030-01-01T00:00:00Z")])
def test_invalid_contract_never_reaches_transport(files, field, value):
    files[4](**{field: value})
    with pytest.raises(ValueError, match="private values withheld"):
        gcp.inventory(files[0], files[1], authorized=True, transport=lambda *a, **k: pytest.fail("Invalid scope transmitted"))


def test_changed_credentials_or_scope_stop_before_next_call(files):
    for path in (files[0], files[1]):
        files[4]()
        report, calls = run(files, [response(context())], after=lambda _: path.write_text("private changed input"))
        assert len(calls) == 1 and report["outcome"] == "authorization-stopped"


@pytest.mark.parametrize("body", [b'{"assets":[],"assets":[]}', b'{"secret":NaN}', b'[]', b'x' * 1048577])
def test_malformed_json_and_size_fail_without_complete_inventory(files, body):
    report, _ = run(files, [response(context()), {"status": 200, "body": body}])
    assert report["outcome"] == "invalid-response" and not report["visible_pagination_exhausted"]


def test_permission_and_create_only_cli_receipt(files, tmp_path, monkeypatch):
    with pytest.raises(PermissionError):
        gcp.inventory("not-read", "not-read", authorized=1)
    def stub(target, token, *, before_send):
        before_send()
        return response(context() if urlsplit(target).netloc == gcp.CONTEXT_HOST else page())
    monkeypatch.setattr(gcp, "_gcp_get", stub)
    output = tmp_path / "gcp-receipt.json"
    args = ["gcp-resource-inventory", "--input", str(files[0]), "--credentials", str(files[1]), "--out", str(output), "--authorized"]
    main(args)
    report = json.loads(output.read_text())
    assert report["assets_retained"] == 1 and report["input_sha256"] == hashlib.sha256(files[0].read_bytes()).hexdigest()
    with pytest.raises(FileExistsError):
        main(args)


@pytest.mark.parametrize("target", ["https://evil.invalid/v1/projects/123/assets", "http://" + gcp.ASSET_HOST + "/v1/projects/123/assets",
    "https://" + gcp.ASSET_HOST + ":443/v1/projects/123/assets", "https://" + gcp.ASSET_HOST + "/v1/organizations/123/assets"])
def test_native_host_and_path_guard_precedes_dns(monkeypatch, target):
    monkeypatch.setattr(gcp, "resolve_pinned", lambda *a: pytest.fail("Rejected target reached DNS"))
    with pytest.raises(ValueError):
        gcp._gcp_get(target, TOKEN, before_send=lambda: None)


def test_tls_debug_keylog_and_expiry_guard(tmp_path, monkeypatch):
    output = tmp_path / "must-not-log-secrets"
    monkeypatch.setenv("SSLKEYLOGFILE", str(output))
    monkeypatch.setattr(gcp.http.client.HTTPConnection, "debuglevel", 1)
    connection = gcp._GCPConnection(gcp.ASSET_HOST, "8.8.8.8")
    assert connection.debuglevel == 0 and connection._context.check_hostname and connection._context.verify_mode == ssl.CERT_REQUIRED
    assert connection._context.keylog_filename is None and not output.exists()
    connection.close()
    monkeypatch.setattr(gcp, "resolve_pinned", lambda *a: "8.8.8.8")
    monkeypatch.setattr(gcp, "_GCPConnection", lambda *a: pytest.fail("Expired authorization opened connection"))
    def stop():
        raise PermissionError("expired")
    with pytest.raises(PermissionError):
        gcp._gcp_get("https://" + gcp.CONTEXT_HOST + "/v3/projects/" + NUMBER, TOKEN, before_send=stop)


def test_real_owned_https_two_service_hosts_and_snapshot_pagination(files, tmp_path, monkeypatch):
    pytest.importorskip("cryptography", reason="Owned HTTPS fixture certificate generation")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned GCP fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, gcp.ASSET_HOST)]))
        .issuer_name(name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(gcp.CONTEXT_HOST), x509.DNSName(gcp.ASSET_HOST)]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256()))
    cert, private_key = tmp_path / "owned-cert.pem", tmp_path / "owned-key.pem"
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    private_key.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    calls, names, snapshot = [], [], stamp()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append((self.headers.get("Host"), self.path, self.headers.get("Authorization")))
            data = context() if len(calls) == 1 else (page(readTime=snapshot, nextPageToken="private-next") if len(calls) == 2 else page([], readTime=snapshot))
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    service = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, private_key)
    tls.set_servername_callback(lambda sock, host, ctx: names.append(host))
    service.socket = tls.wrap_socket(service.socket, server_side=True)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    original = ssl.SSLContext.load_default_certs
    def trust(context, *args, **kwargs):
        original(context, *args, **kwargs)
        context.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM).decode())
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", trust)
    monkeypatch.setattr(gcp, "resolve_pinned", lambda *a: "8.8.8.8")
    monkeypatch.setattr(gcp, "_dial", lambda ip: socket.create_connection(("127.0.0.1", service.server_port), timeout=5))
    try:
        report = gcp.inventory(files[0], files[1], authorized=True, sleeper=lambda _: None)
    finally:
        service.shutdown()
        service.server_close()
        thread.join(5)
    assert not thread.is_alive() and [c[0] for c in calls] == [gcp.CONTEXT_HOST, gcp.ASSET_HOST, gcp.ASSET_HOST]
    assert names == [gcp.CONTEXT_HOST, gcp.ASSET_HOST, gcp.ASSET_HOST]
    assert all(c[2] == "Bearer " + TOKEN for c in calls)
    assert parse_qs(urlsplit(calls[2][1]).query)["readTime"] == [snapshot]
    assert report["visible_pagination_exhausted"] and report["assets_retained"] == 1
    assert TOKEN not in json.dumps(report)
