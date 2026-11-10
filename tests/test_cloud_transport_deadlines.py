"""Deadline conservation and owned TLS slow-drip regressions, without cloud targets."""
import json
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from hunterqa import azure_inventory as azure
from hunterqa import cloud_transport as wire
from hunterqa import gcp_inventory as gcp
from hunterqa import gcp_permissions as permissions
from hunterqa import shared_quota as quota
from hunterqa.engagement import utcnow

SUB = "11111111-2222-3333-4444-555555555555"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PROJECT, NUMBER = "owned-fixture-123", "123456789012"
TOKEN = "owned-synthetic-transport-token-0123456789"


class Channel:
    def __init__(self):
        self.timeouts, self.sent, self.reads, self.closes = [], [], 0, 0
    def settimeout(self, value):
        self.timeouts.append(value)
    def sendall(self, data):
        self.sent.append(data)
    def recv_into(self, buffer):
        self.reads += 1
        buffer[0] = ord("x")
        return 1
    def close(self):
        self.closes += 1


@pytest.fixture
def clock(monkeypatch):
    value = [100.0]
    monkeypatch.setattr(wire, "time", SimpleNamespace(monotonic=lambda: value[0]))
    return value


@pytest.mark.parametrize("provider", ["azure", "gcp"])
def test_connect_time_is_charged_before_tls(provider, clock, monkeypatch):
    module = azure if provider == "azure" else gcp
    connection = azure._ARMConnection("8.8.8.8") if provider == "azure" else gcp._GCPConnection(gcp.CONTEXT_HOST, "8.8.8.8")
    raw = Channel()
    def dial(ip):
        clock[0] = 106.0
        return raw
    monkeypatch.setattr(module, "_dial", dial)
    connection._context = SimpleNamespace(wrap_socket=lambda *a, **k: pytest.fail("Expired TCP budget entered TLS"))
    with pytest.raises(TimeoutError, match="deadline"):
        connection.connect()
    assert raw.closes == 1 and not raw.sent


def test_tls_and_send_share_connect_budget(clock):
    raw, tls, names = Channel(), Channel(), []
    end = wire.deadline()
    clock[0] = 102.0
    def handshake(channel, *, server_hostname):
        names.append(server_hostname)
        clock[0] = 104.0
        return tls
    wrapped = wire.finish_tls(raw, SimpleNamespace(wrap_socket=handshake), "owned.invalid", end)
    wrapped.sendall(b"fixed request")
    wrapped.close()
    assert raw.timeouts == [3.0] and tls.timeouts == [1.0, 1.0]
    assert names == ["owned.invalid"] and tls.sent == [b"fixed request"] and tls.closes == 1


@pytest.mark.parametrize("failure", ["handshake-error", "late-handshake"])
def test_failed_or_late_tls_closes_correct_channel(clock, failure):
    raw, tls = Channel(), Channel()
    def handshake(*a, **k):
        if failure == "handshake-error":
            raise ssl.SSLError("owned synthetic handshake failure")
        clock[0] = 106.0
        return tls
    with pytest.raises((ssl.SSLError, TimeoutError)):
        wire.finish_tls(raw, SimpleNamespace(wrap_socket=handshake), "owned.invalid", wire.deadline())
    assert (raw.closes, tls.closes) == ((1, 0) if failure == "handshake-error" else (0, 1))


def test_frequent_response_bytes_do_not_reset_deadline(clock):
    channel = Channel()
    wrapped = wire.DeadlineSocket(channel, wire.deadline())
    stream = wrapped.makefile("rb")
    assert stream.read(1) == b"x"
    clock[0] = 104.0
    assert stream.read(1) == b"x"
    clock[0] = 106.0
    with pytest.raises(TimeoutError):
        stream.read(1)
    wrapped.close()
    assert channel.closes == 0
    stream.close()
    assert channel.reads == 2 and channel.closes == 1 and wrapped.readers == 0
    assert channel.timeouts == [5.0, 1.0]


@pytest.mark.parametrize("order", ["owner-first", "reader-first", "two-readers", "no-readers"])
def test_connection_close_keeps_response_reader_until_last_reference(order, clock):
    channel = Channel()
    wrapped = wire.DeadlineSocket(channel, wire.deadline())
    streams = [wrapped.makefile() for _ in range(2 if order == "two-readers" else 0 if order == "no-readers" else 1)]
    if order == "reader-first":
        streams[0].close()
        assert channel.closes == 0
    wrapped.close()
    if order in ("owner-first", "two-readers"):
        assert channel.closes == 0 and streams[-1].read(1) == b"x"
    for stream in streams:
        stream.close()
        stream.close()
    wrapped.close()
    assert channel.closes == 1 and wrapped.released and not wrapped.readers


@pytest.mark.parametrize("mode", ["r", "wb", "rwb"])
def test_unsupported_response_stream_modes_do_not_open_reader(mode, clock):
    wrapped = wire.DeadlineSocket(Channel(), wire.deadline())
    with pytest.raises(ValueError):
        wrapped.makefile(mode)
    wrapped.close()
    assert wrapped.readers == 0 and wrapped.channel.closes == 1


@pytest.mark.parametrize("failure", ["encoding", "oversized", "read-error", "interrupt", "success"])
def test_response_reader_always_closes(failure):
    closed = []
    class Response:
        status = 200
        def getheader(self, *args):
            return "gzip" if failure == "encoding" else "identity"
        def read(self, limit):
            assert limit == 5
            if failure == "read-error":
                raise TimeoutError
            if failure == "interrupt":
                raise KeyboardInterrupt
            return b"12345" if failure == "oversized" else b"{}"
        def close(self):
            closed.append(True)
    if failure == "success":
        assert wire.read_response(Response(), 4) == {"status": 200, "body": b"{}"}
    else:
        with pytest.raises((ValueError, TimeoutError, KeyboardInterrupt)):
            wire.read_response(Response(), 4)
    assert closed == [True]


def call_native(kind):
    if kind == "azure":
        return azure._arm_get(azure.ORIGIN + "/subscriptions/" + SUB + "?api-version=2020-01-01", TOKEN, before_send=lambda: None)
    if kind == "gcp":
        return gcp._gcp_get("https://" + gcp.CONTEXT_HOST + "/v3/projects/" + NUMBER, TOKEN, before_send=lambda: None)
    return permissions._permission_post(NUMBER, ["resourcemanager.projects.get"], TOKEN, before_send=lambda: None)


@pytest.mark.parametrize("kind", ["azure", "gcp", "permissions"])
def test_late_authorization_check_after_tls_cannot_transmit_bearer(kind, clock, monkeypatch):
    raw, tls = Channel(), Channel()
    module = azure if kind == "azure" else gcp
    original = module._ARMConnection if kind == "azure" else module._GCPConnection
    def factory(*args):
        connection = original(*args)
        connection._context = SimpleNamespace(wrap_socket=lambda *a, **k: tls)
        return connection
    monkeypatch.setattr(module, "_dial", lambda ip: raw)
    monkeypatch.setattr(azure if kind == "azure" else gcp if kind == "gcp" else permissions,
        "_ARMConnection" if kind == "azure" else "_GCPConnection", factory)
    monkeypatch.setattr(azure if kind == "azure" else gcp if kind == "gcp" else permissions, "resolve_pinned", lambda *a: "8.8.8.8")
    calls = []
    def gate():
        calls.append(True)
        if len(calls) == 3:
            clock[0] = 106.0
    with pytest.raises(TimeoutError):
        if kind == "azure":
            azure._arm_get(azure.ORIGIN + "/subscriptions/" + SUB + "?api-version=2020-01-01", TOKEN, before_send=gate)
        elif kind == "gcp":
            gcp._gcp_get("https://" + gcp.CONTEXT_HOST + "/v3/projects/" + NUMBER, TOKEN, before_send=gate)
        else:
            permissions._permission_post(NUMBER, ["resourcemanager.projects.get"], TOKEN, before_send=gate)
    assert calls == [True, True, True] and not tls.sent and tls.closes == 1


@pytest.mark.parametrize("kind", ["azure", "gcp", "permissions"])
def test_authorization_change_during_trust_setup_prevents_tcp(kind, monkeypatch):
    stopped, closed = [], []
    module = azure if kind == "azure" else gcp if kind == "gcp" else permissions
    monkeypatch.setattr(module, "resolve_pinned", lambda *a: "8.8.8.8")
    class Connection:
        def __init__(self, *args):
            stopped.append(True)
        def connect(self):
            pytest.fail("Expired admission entered TCP after trust-context setup")
        def close(self):
            closed.append(True)
    monkeypatch.setattr(module, "_ARMConnection" if kind == "azure" else "_GCPConnection", Connection)
    def gate():
        if stopped:
            raise PermissionError("owned stop")
    with pytest.raises(PermissionError):
        if kind == "azure":
            azure._arm_get(azure.ORIGIN + "/subscriptions/" + SUB + "?api-version=2020-01-01", TOKEN, before_send=gate)
        elif kind == "gcp":
            gcp._gcp_get("https://" + gcp.CONTEXT_HOST + "/v3/projects/" + NUMBER, TOKEN, before_send=gate)
        else:
            permissions._permission_post(NUMBER, ["resourcemanager.projects.get"], TOKEN, before_send=gate)
    assert closed == [True]


@pytest.fixture(scope="module")
def certificate_files(tmp_path_factory):
    pytest.importorskip("cryptography", reason="Owned TLS slow-response fixture")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    root = tmp_path_factory.mktemp("cloud-deadline-tls")
    now = utcnow()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned deadline CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, azure.HOST)]))
        .issuer_name(name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in (azure.HOST, gcp.CONTEXT_HOST, gcp.ASSET_HOST)]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256()))
    cert, private_key = root / "owned.pem", root / "owned-key.pem"
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    private_key.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert, private_key, ca.public_bytes(serialization.Encoding.PEM).decode()


@contextmanager
def owned_server(certificate_files, mode, *, context_first=False):
    stopped, calls, errors = threading.Event(), [], []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.do_GET()
        def do_GET(self):
            self.close_connection = True
            calls.append((self.command, self.headers.get("Host"), self.headers.get("Authorization")))
            try:
                if context_first and len(calls) == 1:
                    data = ({"id": "/subscriptions/" + SUB, "subscriptionId": SUB, "tenantId": TENANT} if self.headers.get("Host") == azure.HOST
                        else {"name": "projects/" + NUMBER, "projectId": PROJECT, "parent": None, "state": "ACTIVE"})
                    payload = json.dumps(data).encode()
                    self.connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload)
                    return
                if mode in ("length", "chunked", "eof", "keep-alive"):
                    payload = (b"Transfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n" if mode == "chunked" else
                        b"\r\n{}" if mode == "eof" else b"Content-Length: 2\r\n\r\n{}")
                    connection = b"keep-alive" if mode == "keep-alive" else b"close"
                    self.connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: " + connection + b"\r\n" + payload)
                    return
                if mode != "status":
                    self.connection.sendall(b"HTTP/1.1 200 OK\r\n")
                if mode == "headers":
                    self.connection.sendall(b"X-Slow: ")
                elif mode == "body":
                    self.connection.sendall(b"Connection: close\r\nContent-Length: 10000\r\n\r\n")
                elif mode in ("chunk-size", "chunk-data", "trailers"):
                    self.connection.sendall(b"Connection: close\r\nTransfer-Encoding: chunked\r\n\r\n")
                    if mode == "trailers":
                        self.connection.sendall(b"1\r\nx\r\n0\r\nX-Slow: ")
                for _ in range(100):
                    if stopped.is_set():
                        return
                    self.connection.sendall(b"1\r\nx\r\n" if mode == "chunk-data" else b"0" if mode == "chunk-size" else b"x")
                    stopped.wait(0.04)  # Regular activity well inside even the reduced test timeout.
            except (OSError, ssl.SSLError):
                pass  # Deadline rejection intentionally closes the client channel.
            except Exception as exc:
                errors.append(type(exc).__name__)
        def log_message(self, *args):
            pass
    service = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    service.daemon_threads = False
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(*certificate_files[:2])
    service.socket = tls.wrap_socket(service.socket, server_side=True)
    thread = threading.Thread(target=lambda: service.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    try:
        yield service.server_port, calls
    finally:
        stopped.set()
        service.shutdown()
        service.server_close()
        thread.join(3)
        assert not thread.is_alive() and not errors


def route_owned(certificate_files, port, monkeypatch, *, timeout):
    original = ssl.SSLContext.load_default_certs
    def trust(ctx, *args, **kwargs):
        original(ctx, *args, **kwargs)
        ctx.load_verify_locations(cadata=certificate_files[2])
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", trust)
    for module in (azure, gcp, permissions):
        monkeypatch.setattr(module, "resolve_pinned", lambda *a: "8.8.8.8")
    for module in (azure, gcp):
        monkeypatch.setattr(module, "_dial", lambda ip: socket.create_connection(("127.0.0.1", port), timeout=timeout))
    monkeypatch.setattr(wire, "REQUEST_TIMEOUT", timeout)
    original_tls, channels = wire.finish_tls, []
    def observed(*args):
        result = original_tls(*args)
        channels.append(result)
        return result
    monkeypatch.setattr(wire, "finish_tls", observed)
    return channels


@pytest.mark.parametrize("kind", ["azure", "gcp", "permissions"])
@pytest.mark.parametrize("phase", ["status", "headers", "body", "chunk-size", "chunk-data", "trailers"])
def test_actual_tls_regular_slow_drip_cannot_extend_deadline(kind, phase, certificate_files, monkeypatch):
    with owned_server(certificate_files, phase) as (port, calls):
        channels = route_owned(certificate_files, port, monkeypatch, timeout=0.4)
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            call_native(kind)
        elapsed = time.monotonic() - start
    assert 0.25 <= elapsed < 2.5 and len(calls) == 1
    assert calls[0][2] == "Bearer " + TOKEN
    assert len(channels) == 1 and channels[0].released and channels[0].readers == 0
    assert channels[0].channel.fileno() == -1


@pytest.mark.parametrize("kind", ["azure", "gcp", "permissions"])
@pytest.mark.parametrize("framing", ["length", "chunked", "eof", "keep-alive"])
def test_actual_tls_normal_response_framing_and_cleanup(kind, framing, certificate_files, monkeypatch):
    with owned_server(certificate_files, framing) as (port, calls):
        channels = route_owned(certificate_files, port, monkeypatch, timeout=2.0)
        result = call_native(kind)
    assert result == {"status": 200, "body": b"{}"} and len(calls) == 1
    assert channels[0].released and channels[0].readers == 0 and channels[0].channel.fileno() == -1


@pytest.mark.parametrize("kind", ["azure", "gcp", "permissions"])
def test_native_deadline_failure_preserves_context_unknowns_and_quota(kind, certificate_files, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    expiry = (utcnow() + timedelta(hours=1)).isoformat()
    ledger = tmp_path / "owned-quota.sqlite3"
    quota.initialize(ledger, max_requests=2, max_active_runs=1, expires_at=expiry, authorized=True)
    monkeypatch.setenv("HUNTERQA_QUOTA_LEDGER", str(ledger))
    common = {"schema_version": 1, "provider": "azure" if kind == "azure" else "gcp",
        "authorization_reference": "Owned slow-response fixture", "acknowledged_authorization": True,
        "expires_at": expiry, "interval_seconds": 0.5}
    if kind == "azure":
        common.update(subscription_id=SUB, tenant_id=TENANT)
    else:
        common.update(project_id=PROJECT, project_number=NUMBER, expected_parent=None)
    if kind == "permissions":
        common.update(permissions=["resourcemanager.projects.get"])
    else:
        common.update(max_pages=1, page_size=1, max_resources=1)
        if kind == "gcp":
            common.update(read_time=(utcnow() - timedelta(seconds=2)).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
    source, secret = tmp_path / "contract.json", tmp_path / "token.json"
    source.write_text(json.dumps(common), encoding="utf-8")
    secret.write_text(json.dumps({"access_token": TOKEN, "expires_at": expiry}), encoding="utf-8")
    with owned_server(certificate_files, "body", context_first=True) as (port, calls):
        channels = route_owned(certificate_files, port, monkeypatch, timeout=0.4)
        command = azure.inventory if kind == "azure" else gcp.inventory if kind == "gcp" else permissions.check_permissions
        report = command(source, secret, authorized=True, sleeper=lambda _: None)
    assert report["outcome"] == "transport-rejected" and len(calls) == 2
    assert report["subscription_context_matched" if kind == "azure" else "project_context_matched"]
    assert report["requests_completed"] == 1 and report["shared_quota"]["reservation_released"] is True
    assert all(channel.released and channel.channel.fileno() == -1 for channel in channels)
    assert quota.status(ledger)["charged_requests"] == 2 and quota.status(ledger)["active_runs"] == 0
    if kind == "permissions":
        assert report["permissions"][0]["provider_reported_granted"] is None
        assert not report["permission_query_completed"]
    else:
        assert not report["inventory_complete"] and not report["visible_pagination_exhausted"]
    assert TOKEN not in json.dumps(report)
