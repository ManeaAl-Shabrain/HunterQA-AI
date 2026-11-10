"""Owned provider-response controls; no real Google Cloud project is contacted."""
import json
import socket
import ssl
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from hunterqa import gcp_inventory as gcp
from hunterqa import gcp_permissions as module
from hunterqa import shared_quota as quota
from hunterqa.cli import main
from hunterqa.engagement import utcnow

PROJECT, NUMBER, PARENT = "owned-fixture-123", "123456789012", "folders/123456789"
TOKEN = "synthetic-private-permission-bearer-0123456789"
READ, WRITE = "resourcemanager.projects.get", "resourcemanager.projects.setIamPolicy"


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER", raising=False)
    data = {"schema_version": 1, "provider": "gcp", "project_id": PROJECT, "project_number": NUMBER,
        "expected_parent": PARENT, "authorization_reference": "Owned exact-project permission query",
        "acknowledged_authorization": True, "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(),
        "permissions": [READ, WRITE], "interval_seconds": 0.5}
    keys = {"access_token": TOKEN, "expires_at": (utcnow() + timedelta(minutes=15)).isoformat()}
    source, secret = tmp_path / "contract.json", tmp_path / "token.json"
    def save(**changes):
        data.update(changes)
        source.write_text(json.dumps(data), encoding="utf-8")
        secret.write_text(json.dumps(keys), encoding="utf-8")
    save()
    return source, secret, data, keys, save


def context(**changes):
    return {"name": "projects/" + NUMBER, "projectId": PROJECT, "parent": PARENT, "state": "ACTIVE", **changes}


def response(data, status=200):
    return {"status": status, "body": json.dumps(data).encode()}


def run(files, permission_response=None, *, context_response=None, after=None):
    calls = []
    def get(target, token, *, before_send):
        before_send()
        assert urlsplit(target).netloc == gcp.CONTEXT_HOST and token == TOKEN
        calls.append("context")
        if after:
            after("context")
        return context_response if context_response is not None else response(context())
    def post(number, permissions, token, *, before_send):
        before_send()
        assert number == NUMBER and permissions == files[2]["permissions"] and token == TOKEN
        calls.append("permissions")
        if after:
            after("permissions")
        return permission_response if permission_response is not None else response({"permissions": [READ]})
    report = module.check_permissions(files[0], files[1], authorized=True,
        context_transport=get, permission_transport=post, sleeper=lambda _: None)
    return report, calls


@pytest.mark.parametrize("values", [[READ], [WRITE], [WRITE, READ], []])
def test_selected_response_subset_is_not_complete_effective_access(files, values):
    report, calls = run(files, response({"permissions": values}))
    assert calls == ["context", "permissions"] and report["permission_query_completed"]
    assert report["outcome"] == "permission-response-observed" and report["project_context_matched"]
    assert report["permissions"] == [{"permission": p, "provider_reported_granted": p in values} for p in (READ, WRITE)]
    assert report["requests_completed"] == 2 and len(report["receipts"]) == 2
    assert not report["principal_identity_verified"] and not report["effective_permissions_verified"]
    assert not report["owner_grant_verified"] and report["findings"] == []
    for private in (TOKEN, PROJECT, NUMBER, PARENT, str(files[0]), str(files[1])):
        assert private not in json.dumps(report)


def test_omitted_repeated_field_is_empty_not_failure(files):
    report, _ = run(files, response({}))
    assert report["permission_query_completed"]
    assert all(r["provider_reported_granted"] is False for r in report["permissions"])


@pytest.mark.parametrize("changes", [{"name": "projects/999"}, {"projectId": "other-project"},
    {"parent": "organizations/123456789"}, {"state": "DELETE_REQUESTED"}, {"parent": None}])
def test_wrong_context_blocks_permission_query_with_unknowns(files, changes):
    report, calls = run(files, context_response=response(context(**changes)))
    assert calls == ["context"] and report["outcome"] == "project-context-mismatch"
    assert not report["permission_query_completed"]
    assert all(r["provider_reported_granted"] is None for r in report["permissions"])


@pytest.mark.parametrize("data", [None, [], {"permissions": None}, {"permissions": "secret"},
    {"permissions": [READ, READ]}, {"permissions": ["resourcemanager.projects.delete"]},
    {"permissions": [True]}, {"permissions": [{}]}, {"permissions": [READ], "unexpected": "private"},
    {"permissions": [READ] * 6}])
def test_invalid_permission_response_is_unknown_not_false(files, data):
    report, _ = run(files, response(data))
    assert report["outcome"] == "invalid-response" and not report["permission_query_completed"]
    assert all(r["provider_reported_granted"] is None for r in report["permissions"])
    assert "secret" not in json.dumps(report) and "unexpected" not in json.dumps(report)


@pytest.mark.parametrize("status", [301, 401, 403, 404, 429, 500])
@pytest.mark.parametrize("stage", ["context", "permissions"])
def test_http_errors_no_redirect_retry_or_negative_permission_claim(files, status, stage):
    error = response({"error": "private-provider-detail", "location": "https://evil.invalid"}, status)
    report, calls = run(files, error if stage == "permissions" else None,
        context_response=error if stage == "context" else None)
    assert calls == (["context"] if stage == "context" else ["context", "permissions"])
    assert report["outcome"] == "http-error" and not report["permission_query_completed"]
    assert all(r["provider_reported_granted"] is None for r in report["permissions"])
    assert "private-provider-detail" not in json.dumps(report) and "evil.invalid" not in json.dumps(report)


@pytest.mark.parametrize("bad", [{"status": True, "body": b"{}"}, {"status": 600, "body": b"{}"},
    {"status": 200, "body": "{}"}, {"status": 200, "body": b"x" * 16385},
    {"status": 200, "body": b'{"permissions":[],"permissions":[]}'},
    {"status": 200, "body": b"{"}, {"status": 200, "body": b'{"x":NaN}'}])
def test_transport_and_json_response_bounds(files, bad):
    report, _ = run(files, bad)
    assert report["outcome"] == "invalid-response" and not report["permission_query_completed"]


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("provider", "azure"), ("project_id", "OtherProject"),
    ("project_number", "00123"), ("project_number", "123/../999"), ("expected_parent", "folders/001"),
    ("acknowledged_authorization", 1), ("authorization_reference", ""),
    ("expires_at", "2000-01-01T00:00:00Z"), ("expires_at", "2100-01-01T00:00:00Z"),
    ("permissions", []), ("permissions", [READ, READ]), ("permissions", ["*"]),
    ("permissions", ["resourcemanager.projects.*"]), ("permissions", ["storage.buckets.list"]),
    ("permissions", [{}]), ("permissions", "private"), ("interval_seconds", True),
    ("interval_seconds", 0.1), ("interval_seconds", 6), ("extra", "private")])
def test_invalid_contract_precedes_transport(files, field, value):
    files[4](**{field: value})
    def forbidden(*a, **k):
        pytest.fail("Invalid contract reached network")
    with pytest.raises(ValueError, match="private values withheld"):
        module.check_permissions(files[0], files[1], authorized=True,
            context_transport=forbidden, permission_transport=forbidden)


@pytest.mark.parametrize("change", [{"access_token": "short"}, {"access_token": "secret\r\nInjected: value"},
    {"expires_at": "2000-01-01T00:00:00Z"}, {"extra": "private"}])
def test_bad_temporary_credentials_block_before_network(files, change):
    files[3].update(change)
    files[4]()
    with pytest.raises(ValueError, match="contents withheld"):
        module.check_permissions(files[0], files[1], authorized=True,
            context_transport=lambda *a, **k: pytest.fail("Bad token reached network"))


@pytest.mark.parametrize("change", ["contract", "token", "expiry", "remove"])
def test_changes_after_context_stop_before_post(files, change):
    def mutate(stage):
        if change == "remove":
            files[0].unlink()
        elif change == "token":
            files[3]["access_token"] = TOKEN + "changed"
            files[4]()
        else:
            files[4](**({"permissions": [READ]} if change == "contract" else {"expires_at": "2000-01-01T00:00:00Z"}))
    report, calls = run(files, after=mutate)
    assert calls == ["context"] and report["outcome"] == "authorization-stopped"
    assert report["project_context_matched"] and all(p["provider_reported_granted"] is None for p in report["permissions"])


@pytest.fixture
def ledger(files, tmp_path, monkeypatch):
    path = tmp_path / "permissions-quota.sqlite3"
    quota.initialize(path, max_requests=2, max_active_runs=1,
        expires_at=(utcnow() + timedelta(hours=1)).isoformat(), authorized=True)
    monkeypatch.setenv("HUNTERQA_QUOTA_LEDGER", str(path))
    return path


def test_shared_quota_charges_two_releases_and_denies_next_call(files, ledger):
    def inspect(stage):
        state = quota.status(ledger)
        assert state["active_runs"] == 1 and state["charged_requests"] == 2
    report, _ = run(files, after=inspect)
    assert report["shared_quota"]["reservation_released"] is True
    state = quota.status(ledger)
    assert state["active_runs"] == 0 and state["charged_requests"] == 2
    with pytest.raises(PermissionError):
        run(files)
    assert str(ledger) not in json.dumps(report)


@pytest.mark.parametrize("change", ["stop", "unset"])
def test_quota_stop_between_calls_preserves_unknowns(files, ledger, monkeypatch, change):
    def mutate(stage):
        if change == "stop":
            quota.stop(ledger, authorized=True)
        else:
            monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER")
    report, calls = run(files, after=mutate)
    assert calls == ["context"] and report["outcome"] == "quota-stopped"
    assert quota.status(ledger)["charged_requests"] == 2 and quota.status(ledger)["active_runs"] == 0


def test_context_failure_does_not_refund_reservation(files, ledger):
    report, _ = run(files, context_response=response({}, 403))
    assert report["outcome"] == "http-error" and quota.status(ledger)["charged_requests"] == 2
    assert quota.status(ledger)["active_runs"] == 0


def test_authorization_and_output_scope_precede_execution(files, tmp_path, monkeypatch):
    with pytest.raises(PermissionError):
        module.check_permissions(files[0], files[1])
    monkeypatch.setattr(module, "check_permissions", lambda *a, **k: pytest.fail("Output guard reached execution"))
    existing = tmp_path / "keep.json"
    existing.write_text("retain")
    for path, exception in ((existing, FileExistsError), (tmp_path.parent / "outside.json", ValueError)):
        with pytest.raises(exception):
            main(["gcp-permission-check", "--input", str(files[0]), "--credentials", str(files[1]),
                  "--out", str(path), "--authorized"])
    assert existing.read_text() == "retain"


@pytest.mark.parametrize("number,permissions", [("123/evil", [READ]), ("00123", [READ]),
    (NUMBER, ["*"]), (NUMBER, [READ, READ]), (NUMBER, [])])
def test_post_boundary_rejects_arbitrary_resource_or_permission_before_dns(monkeypatch, number, permissions):
    monkeypatch.setattr(module, "resolve_pinned", lambda *a: pytest.fail("Bad POST reached DNS"))
    with pytest.raises(ValueError):
        module._permission_post(number, permissions, TOKEN, before_send=lambda: None)


def test_stop_after_tls_prevents_bearer_or_post(monkeypatch):
    operations = []
    monkeypatch.setattr(module, "resolve_pinned", lambda *a: "8.8.8.8")
    class Connection:
        def __init__(self, host, ip):
            assert host == gcp.CONTEXT_HOST and ip == "8.8.8.8"
        def connect(self):
            operations.append("tls")
        def request(self, *a, **k):
            pytest.fail("Stopped request transmitted bearer")
        def close(self):
            operations.append("closed")
    def gate():
        if operations:
            raise PermissionError("stopped")
    monkeypatch.setattr(module, "_GCPConnection", Connection)
    with pytest.raises(PermissionError):
        module._permission_post(NUMBER, [READ], TOKEN, before_send=gate)
    assert operations == ["tls", "closed"]


@pytest.mark.parametrize("encoding,size,accepted", [("identity", 2, True), ("gzip", 2, False),
    ("identity", 16384, True), ("identity", 16385, False)])
def test_post_wire_bounds_fixed_body_and_connection_cleanup(monkeypatch, encoding, size, accepted):
    calls, closed, reads = [], [], []
    monkeypatch.setattr(module, "resolve_pinned", lambda *a: "8.8.8.8")
    class Response:
        status = 200
        def close(self):
            pass
        def getheader(self, key, default=None):
            return encoding
        def read(self, cap):
            reads.append(cap)
            return b"x" * size
    class Connection:
        def __init__(self, host, ip):
            assert host == gcp.CONTEXT_HOST and ip == "8.8.8.8"
        def connect(self):
            pass
        def request(self, method, path, *, body, headers):
            calls.append((method, path, body, headers))
        def getresponse(self):
            return Response()
        def close(self):
            closed.append(True)
    monkeypatch.setattr(module, "_GCPConnection", Connection)
    if accepted:
        result = module._permission_post(NUMBER, [READ, WRITE], TOKEN, before_send=lambda: None)
        assert len(result["body"]) == size
    else:
        with pytest.raises(ValueError):
            module._permission_post(NUMBER, [READ, WRITE], TOKEN, before_send=lambda: None)
    assert closed == [True] and len(calls) == 1
    method, path, body, headers = calls[0]
    assert method == "POST" and path == "/v3/projects/" + NUMBER + ":testIamPermissions"
    assert json.loads(body) == {"permissions": [READ, WRITE]} and set(headers) == {
        "Authorization", "Accept", "Accept-Encoding", "Content-Type", "Connection", "User-Agent"}
    assert headers["Authorization"] == "Bearer " + TOKEN
    assert reads == ([] if encoding != "identity" else [16385])


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1"])
def test_public_dns_admission_blocks_private_and_mixed_answers_before_bearer(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))])
    monkeypatch.setattr(module, "_GCPConnection", lambda *a: pytest.fail("Unsafe DNS reached bearer transport"))
    with pytest.raises(ValueError, match="Unsafe DNS"):
        module._permission_post(NUMBER, [READ], TOKEN, before_send=lambda: None)


def test_full_supported_permission_set_and_no_parent_context(files):
    files[4](permissions=sorted(module.PERMISSIONS), expected_parent=None)
    report, _ = run(files, response({"permissions": sorted(module.PERMISSIONS)}), context_response=response(context(parent=None)))
    assert report["permission_query_completed"] and report["parent_ref"] is None
    assert len(report["permissions"]) == 5 and all(p["provider_reported_granted"] is True for p in report["permissions"])


def test_actual_owned_https_context_then_fixed_readonly_post(files, tmp_path, monkeypatch):
    pytest.importorskip("cryptography", reason="Owned TLS fixture certificate generation")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    now = utcnow()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned permission fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, gcp.CONTEXT_HOST)]))
        .issuer_name(name).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(gcp.CONTEXT_HOST)]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256()))
    cert, private_key = tmp_path / "owned.pem", tmp_path / "owned-key.pem"
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    private_key.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    calls, names = [], []
    class Handler(BaseHTTPRequestHandler):
        def reply(self, data):
            raw = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def do_GET(self):
            calls.append(("GET", self.path, self.headers.get("Host"), self.headers.get("Authorization"), None))
            self.reply(context())
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append(("POST", self.path, self.headers.get("Host"), self.headers.get("Authorization"), body))
            self.reply({"permissions": [READ]})
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
    def trust(ctx, *a, **k):
        original(ctx, *a, **k)
        ctx.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM).decode())
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", trust)
    monkeypatch.setattr(gcp, "resolve_pinned", lambda *a: "8.8.8.8")
    monkeypatch.setattr(module, "resolve_pinned", lambda *a: "8.8.8.8")
    monkeypatch.setattr(gcp, "_dial", lambda ip: socket.create_connection(("127.0.0.1", service.server_port), timeout=5))
    output = tmp_path / "owned-receipt.json"
    try:
        main(["gcp-permission-check", "--input", str(files[0]), "--credentials", str(files[1]), "--out", str(output), "--authorized"])
    finally:
        service.shutdown()
        service.server_close()
        thread.join(5)
    assert not thread.is_alive() and names == [gcp.CONTEXT_HOST] * 2
    assert [c[0] for c in calls] == ["GET", "POST"] and all(c[2] == gcp.CONTEXT_HOST and c[3] == "Bearer " + TOKEN for c in calls)
    assert calls[1][1] == "/v3/projects/" + NUMBER + ":testIamPermissions"
    assert json.loads(calls[1][4]) == {"permissions": [READ, WRITE]}
    report = json.loads(output.read_text())
    assert report["outcome"] == "permission-response-observed" and report["permissions"][0]["provider_reported_granted"] is True
    assert report["permissions"][1]["provider_reported_granted"] is False and TOKEN not in output.read_text()
