"""Exact-scope Azure contract controls; never contact a real Azure subscription."""
import hashlib
import json
import socket
import ssl
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import timedelta
from urllib.parse import urlencode

import pytest

from hunterqa import azure_inventory as azure
from hunterqa.cli import main
from hunterqa.engagement import utcnow

SUB = "11111111-2222-3333-4444-555555555555"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER = "00000000-1111-2222-3333-444444444444"
TOKEN = "synthetic-private-bearer-0123456789"
BASE = azure.ORIGIN + "/subscriptions/" + SUB


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    data = {"schema_version": 1, "provider": "azure", "subscription_id": SUB, "tenant_id": TENANT,
        "authorization_reference": "Private written subscription grant", "acknowledged_authorization": True,
        "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(), "max_pages": 2,
        "page_size": 2, "max_resources": 4, "interval_seconds": 0.5}
    keys = {"access_token": TOKEN, "expires_at": (utcnow() + timedelta(minutes=15)).isoformat()}
    contract, credentials = tmp_path / "azure-contract.json", tmp_path / "azure-secret.json"
    def save(**changes):
        data.update(changes)
        contract.write_text(json.dumps(data), encoding="utf-8")
        credentials.write_text(json.dumps(keys), encoding="utf-8")
    save()
    return contract, credentials, data, keys, save


def resource(name="private-vm", kind="Microsoft.Compute/virtualMachines", subscription=SUB):
    return {"id": f"/subscriptions/{subscription}/resourceGroups/private-group/providers/{kind}/{name}",
            "type": kind, "name": name, "tags": {"secret-tag": "private-tag-value"}, "properties": {"private": "not-exported"}}


def response(data, status=200):
    return {"status": status, "body": json.dumps(data).encode()}


def context(**changes):
    return {"id": "/subscriptions/" + SUB, "subscriptionId": SUB, "tenantId": TENANT,
            "displayName": "private subscription display name", **changes}


def continuation(token="private-continuation"):
    return BASE + "/resources?" + urlencode({"api-version": "2021-04-01", "$skiptoken": token, "$top": "2"})


def run(files, pages, *, after=None, **kwargs):
    calls = []
    def transport(target, token, *, before_send):
        before_send()
        assert token == TOKEN and target.startswith(BASE)
        calls.append(target)
        result = pages[len(calls) - 1]
        if after:
            after(len(calls))
        return result
    report = azure.inventory(files[0], files[1], authorized=True, transport=transport, sleeper=lambda _: None, **kwargs)
    return report, calls


def test_context_then_bounded_pages_deduplicate_and_withhold_private_fields(files):
    report, calls = run(files, [response(context()), response({"value": [resource()], "nextLink": continuation()}),
        response({"value": [resource(), resource("private-storage", "Microsoft.Storage/storageAccounts")]})])
    assert len(calls) == report["requests_attempted"] == report["requests_completed"] == 3
    assert calls[0] == BASE + "?api-version=2022-12-01"
    assert report["subscription_context_matched"] and report["visible_pagination_exhausted"]
    assert report["outcome"] == "visible-pages-exhausted" and report["pages_observed"] == 2
    assert report["resources_retained"] == 2 and report["duplicates_not_retained"] == 1
    assert {r["kind"] for r in report["resources"]} == {"virtual-machine", "storage-account"}
    assert not report["inventory_complete"] and not report["effective_permissions_verified"] and not report["owner_grant_verified"]
    text = json.dumps(report)
    for private in (TOKEN, SUB, TENANT, "private-group", "private-vm", "private-tag-value", "not-exported", "private-continuation", str(files[1])):
        assert private not in text
    assert report["findings"] == []


@pytest.mark.parametrize("changes", [{"subscriptionId": OTHER}, {"tenantId": OTHER}, {"id": "/subscriptions/" + OTHER}])
def test_context_mismatch_prevents_resource_call(files, changes):
    report, calls = run(files, [response(context(**changes))])
    assert len(calls) == 1 and report["outcome"] == "subscription-context-mismatch"
    assert not report["subscription_context_matched"] and report["pages_observed"] == 0


@pytest.mark.parametrize("link", [
    "http://management.azure.com/subscriptions/" + SUB + "/resources?api-version=2021-04-01&$skiptoken=x",
    "https://evil.invalid/?stolen=secret", "https://management.azure.com.evil.invalid/",
    "https://user:pass@management.azure.com/", "https://management.azure.com:443/",
    azure.ORIGIN + "/subscriptions/" + OTHER + "/resources?api-version=2021-04-01&$skiptoken=x",
    continuation() + "#fragment", continuation() + "&$filter=secret", continuation() + "&api-version=2021-04-01",
    continuation().replace("2021-04-01", "2099-01-01"), continuation().replace("%24top=2", "%24top=50"),
    continuation().replace("/resources", "/providers/Microsoft.Authorization/permissions"),
    continuation().replace("/resources", "/%72esources"), continuation().replace("/resources", "/../resources"),
    continuation().replace("private-continuation", "%0D%0AX-Injected%3Asecret"),
    continuation().replace("private-continuation", "x" * 2049), "//management.azure.com/resources", 7])
def test_untrusted_next_link_never_expands_scope(files, link):
    report, calls = run(files, [response(context()), response({"value": [resource()], "nextLink": link})])
    assert len(calls) == 2 and report["outcome"] == "next-link-rejected"
    assert report["resources_retained"] == 1 and not report["visible_pagination_exhausted"]


def test_repeated_pagination_token_is_not_requested_twice(files):
    files[4](max_pages=5)
    report, calls = run(files, [response(context()), response({"value": [], "nextLink": continuation()}),
        response({"value": [], "nextLink": continuation()})])
    assert len(calls) == 3 and report["outcome"] == "pagination-loop"


@pytest.mark.parametrize("field,value,outcome", [("max_pages", 1, "page-limit"), ("max_resources", 1, "resource-limit")])
def test_request_and_retention_limits_stop_incomplete(files, field, value, outcome):
    files[4](**{field: value})
    report, calls = run(files, [response(context()), response({"value": [resource(), resource("vm2")], "nextLink": continuation()})])
    assert len(calls) == 2 and report["outcome"] == outcome and not report["visible_pagination_exhausted"]
    assert report["resources_retained"] <= files[2]["max_resources"]


@pytest.mark.parametrize("status", [301, 302, 401, 403, 429, 500])
def test_http_error_redirect_and_throttling_do_not_retry(files, status):
    report, calls = run(files, [response(context()), response({"error": {"message": TOKEN}}, status)])
    assert len(calls) == 2 and report["outcome"] == "http-error"
    assert report["resources_retained"] == 0 and TOKEN not in json.dumps(report)


@pytest.mark.parametrize("bad", [resource(subscription=OTHER), {"id": "/subscriptions/" + SUB, "type": "bad"},
    {"id": resource()["id"], "type": "Microsoft.Storage/storageAccounts"},
    {"id": resource()["id"] + "/../secret", "type": resource()["type"]},
    {"id": resource()["id"] + "%2Fsecret", "type": resource()["type"]}, None])
def test_invalid_or_cross_subscription_resource_does_not_commit_page(files, bad):
    report, calls = run(files, [response(context()), response({"value": [resource(), bad]})])
    assert len(calls) == 2 and report["outcome"] == "invalid-response" and report["resources"] == []


def test_credential_or_contract_change_stops_next_request(files):
    for changed in (files[0], files[1]):
        files[4]()
        report, calls = run(files, [response(context())], after=lambda n: changed.write_text("changed-private-value"))
        assert len(calls) == 1 and report["outcome"] == "authorization-stopped"
        assert report["requests_attempted"] == 1 and "changed-private-value" not in json.dumps(report)


@pytest.mark.parametrize("field,value", [("schema_version", True), ("provider", "gcp"),
    ("subscription_id", "*"), ("tenant_id", "secret"), ("max_pages", 6), ("max_pages", True),
    ("page_size", 101), ("max_resources", 501), ("interval_seconds", 0), ("interval_seconds", float("nan")),
    ("acknowledged_authorization", 1), ("expires_at", "2020-01-01T00:00:00+00:00")])
def test_invalid_scope_rejected_before_transport(files, field, value):
    files[4](**{field: value})
    with pytest.raises(ValueError, match="private values withheld"):
        azure.inventory(files[0], files[1], authorized=True, transport=lambda *a, **k: pytest.fail("Invalid scope reached transport"))


@pytest.mark.parametrize("token", ["short", TOKEN + "\r\nSecret: injection", "non-ascii-\u0627" * 10, "x" * 16385])
def test_bad_token_never_reaches_transport(files, token):
    files[3]["access_token"] = token
    files[4]()
    with pytest.raises(ValueError, match="contents withheld"):
        azure.inventory(files[0], files[1], authorized=True, transport=lambda *a, **k: pytest.fail("Bad token transmitted"))


def test_permission_before_input_and_private_create_only_cli(files, tmp_path, monkeypatch):
    with pytest.raises(PermissionError):
        azure.inventory("not-read", "not-read", authorized=1)
    def native_stub(target, token, *, before_send):
        before_send()
        return response(context() if "/resources?" not in target else {"value": [resource()]})
    monkeypatch.setattr(azure, "_arm_get", native_stub)
    output = tmp_path / "azure-receipt.json"
    main(["azure-resource-inventory", "--input", str(files[0]), "--credentials", str(files[1]), "--out", str(output), "--authorized"])
    report = json.loads(output.read_text())
    assert report["resources_retained"] == 1 and report["input_sha256"] == hashlib.sha256(files[0].read_bytes()).hexdigest()
    with pytest.raises(FileExistsError):
        main(["azure-resource-inventory", "--input", str(files[0]), "--credentials", str(files[1]), "--out", str(output), "--authorized"])


def test_tls_context_suppresses_keylog_and_http_debug(tmp_path, monkeypatch):
    path = tmp_path / "must-not-export-tls-secrets.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(path))
    monkeypatch.setattr(azure.http.client.HTTPConnection, "debuglevel", 1)
    connection = azure._ARMConnection("8.8.8.8")
    assert connection.debuglevel == 0 and connection._context.check_hostname
    assert connection._context.verify_mode == ssl.CERT_REQUIRED and connection._context.keylog_filename is None
    assert not path.exists()
    connection.close()


def test_native_transport_gate_after_dns_precedes_connection(monkeypatch):
    monkeypatch.setattr(azure, "resolve_pinned", lambda *a: "8.8.8.8")
    monkeypatch.setattr(azure, "_ARMConnection", lambda *a: pytest.fail("Expired authorization opened connection"))
    def expired():
        raise PermissionError("stopped")
    with pytest.raises(PermissionError):
        azure._arm_get(BASE + "?api-version=2022-12-01", TOKEN, before_send=expired)


def test_native_transport_refuses_unsafe_dns_before_token(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    monkeypatch.setattr(azure, "_ARMConnection", lambda *a: pytest.fail("Unsafe DNS opened connection"))
    with pytest.raises(ValueError, match="Unsafe DNS"):
        azure._arm_get(BASE + "?api-version=2022-12-01", TOKEN, before_send=lambda: None)


@pytest.mark.parametrize("body", [b'{"value":[],"value":[]}', b'{"value":[],"private":NaN}',
    b'{"value": [}', b'[]', b'{"value":null}', b'x' * 1048577])
def test_malformed_duplicate_nonfinite_or_oversized_body_does_not_establish_inventory(files, body):
    report, calls = run(files, [response(context()), {"status": 200, "body": body}])
    assert len(calls) == 2 and report["outcome"] == "invalid-response"
    assert not report["visible_pagination_exhausted"] and report["resources_retained"] == 0


def test_real_owned_https_pagination_uses_verified_context_and_fixed_bearer_host(files, tmp_path, monkeypatch):
    pytest.importorskip("cryptography", reason="Owned HTTPS fixture certificate generation")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned transport fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False).sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, azure.HOST)]))
        .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(azure.HOST)]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False).sign(ca_key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "owned-https.pem", tmp_path / "owned-https.key"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    calls, dials, names = [], [], []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append((self.path, self.headers.get("Authorization"), self.headers.get("Host")))
            payload = context() if len(calls) == 1 else ({"value": [resource()], "nextLink": continuation()} if len(calls) == 2 else {"value": []})
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    service = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    server_context.set_servername_callback(lambda sock, name, ctx: names.append(name))
    service.socket = server_context.wrap_socket(service.socket, server_side=True)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    original_load = ssl.SSLContext.load_default_certs
    def trusted_fixture(context, *args, **kwargs):
        original_load(context, *args, **kwargs)
        context.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM).decode())
    def fixture_dial(ip):
        dials.append(ip)
        return socket.create_connection(("127.0.0.1", service.server_port), timeout=5)
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", trusted_fixture)
    monkeypatch.setattr(azure, "resolve_pinned", lambda *a: "8.8.8.8")
    monkeypatch.setattr(azure, "_dial", fixture_dial)  # Owned-only test routing; CLI exposes no endpoint override.
    try:
        report = azure.inventory(files[0], files[1], authorized=True, sleeper=lambda _: None)
    finally:
        service.shutdown()
        service.server_close()
        thread.join(5)
    assert not thread.is_alive() and len(calls) == 3
    assert dials == ["8.8.8.8"] * 3 and names == [azure.HOST] * 3
    assert all(auth == "Bearer " + TOKEN and host == azure.HOST for _, auth, host in calls)
    assert calls[0][0] == "/subscriptions/" + SUB + "?api-version=2022-12-01"
    assert report["visible_pagination_exhausted"] and report["resources_retained"] == 1
    assert TOKEN not in json.dumps(report)
