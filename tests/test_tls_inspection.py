"""Owned TLS server controls and pre-network scope/privacy regressions."""
import hashlib
import json
import socket
import ssl
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from hunterqa import tls_inspection as module
from hunterqa.cli import main


@pytest.fixture
def profile(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    # Controlled DNS answer for the owned IPv4 server, independent of host IPv6 settings.
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, **kwargs:
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))])
    data = {"program": "Owned TLS controls", "platform": "private",
        "authorization_reference": "Written loopback fixture permission",
        "acknowledged_authorization": True, "allowed_hosts": ["localhost"],
        "allowed_paths": ["/"], "methods": ["HEAD"], "allowed_ports": [443],
        "max_requests": 1, "interval_seconds": 0.5,
        "lab_mode": True, "allow_private_network": True}
    path = tmp_path / "profile.json"
    def save(**changes):
        data.update(changes)
        path.write_text(json.dumps(data), encoding="utf-8")
        return path
    save()
    return path, save


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    pytest.importorskip("cryptography", reason="TLS fixture certificate generation uses optional identity extra")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    root = tmp_path_factory.mktemp("tls-certificates")
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Private owned fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256()))
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    result = {"ca": ca_pem}
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = root / "private-key.pem"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    for variant in ("valid", "mismatch", "expired"):
        dns = "other.invalid" if variant == "mismatch" else "localhost"
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)]))
            .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now - timedelta(days=1) if variant == "expired" else now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
        cert_path = root / (variant + ".pem")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        result[variant] = (cert_path, key_path, hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())
    return result


@contextmanager
def server(certificates, variant="valid", *, plaintext=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*certificates[variant][:2])
    context.set_alpn_protocols(["http/1.1"])
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    received, sni, errors = [], [], []
    context.set_servername_callback(lambda sock, name, ctx: sni.append(name))
    def serve():
        try:
            with listener.accept()[0] as conn:
                conn.settimeout(3)
                if plaintext:
                    conn.recv(8192)  # Consume ClientHello before returning a non-TLS response.
                    conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    conn.recv(1024)
                else:
                    with context.wrap_socket(conn, server_side=True) as tls:
                        received.append(tls.recv(1024))
        except (ssl.SSLError, ConnectionResetError):
            pass  # Expected for intentionally rejected certificates.
        except Exception as exc:
            errors.append(type(exc).__name__)
        finally:
            listener.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], received, sni
    finally:
        thread.join(6)
        listener.close()
        assert not thread.is_alive()
        assert not errors


@pytest.mark.parametrize("variant,trust,expected", [
    ("valid", True, "verified"), ("valid", False, "certificate-rejected"),
    ("expired", True, "certificate-rejected"), ("mismatch", True, "certificate-rejected")])
def test_real_tls_certificate_controls(profile, certificates, tmp_path, variant, trust, expected):
    path, save = profile
    ca = tmp_path / "public-ca.pem"
    ca.write_bytes(certificates["ca"])
    with server(certificates, variant) as (port, received, sni):
        save(allowed_ports=[port])
        target = f"https://localhost:{port}/"
        report = module.inspect_service(path, target, authorized=True, ca_file=ca if trust else None)
    assert report["outcome"] == expected
    assert report["connection_attempts"] == 1 and report["http_requests"] == 0
    assert report["certificate_and_hostname_verified"] is (expected == "verified")
    if expected == "verified":
        assert received == [b""] and sni == ["localhost"]
        assert report["tls_version"] == "TLSv1.2"
        assert report["alpn"] == "http/1.1"
        assert report["leaf_certificate_sha256"] == certificates[variant][2]
        assert report["cipher"]["bits"] >= 128
    else:
        assert report["leaf_certificate_sha256"] is None and report["tls_version"] is None
        assert type(report["certificate_verification_code"]) is int
    serialized = json.dumps(report)
    for secret in (target, "localhost", "other.invalid", "Private owned fixture CA", str(ca), "BEGIN CERTIFICATE"):
        assert secret not in serialized
    assert not report["revocation_verified"] and not report["service_product_verified"]
    assert report["findings"] == []


def test_plaintext_is_tls_error_without_http_fallback(profile, certificates, tmp_path):
    path, save = profile
    with server(certificates, plaintext=True) as (port, _, _):
        save(allowed_ports=[port])
        report = module.inspect_service(path, f"https://localhost:{port}/", authorized=True)
    assert report["outcome"] == "tls-error"
    assert report["connection_attempts"] == 1 and report["http_requests"] == 0
    assert report["certificate_and_hostname_verified"] is None


@pytest.mark.parametrize("target", ["http://localhost/", "https://localhost/private", "https://localhost/?x=1",
    "https://localhost/#fragment", "https://other.invalid/", "https://localhost:444/", "https://user:pass@localhost/"])
def test_scope_rejection_precedes_dns(profile, monkeypatch, target):
    def forbidden(*args):
        pytest.fail("Rejected target reached DNS")
    monkeypatch.setattr(module, "resolve_pinned", forbidden)
    with pytest.raises(ValueError):
        module.inspect_service(profile[0], target, authorized=True)


@pytest.mark.parametrize("authorized", [False, None, 1, "yes"])
def test_permission_required_before_loading_or_network(authorized):
    with pytest.raises(PermissionError):
        module.inspect_service("nonexistent", "https://localhost/", authorized=authorized)


def test_path_only_permission_does_not_authorize_host_handshake(profile, monkeypatch):
    path, save = profile
    save(allowed_paths=["/app"])
    monkeypatch.setattr(module, "resolve_pinned", lambda *args: pytest.fail("Path-only scope reached DNS"))
    with pytest.raises(ValueError):
        module.inspect_service(path, "https://localhost/", authorized=True)


@pytest.mark.parametrize("pem", [b"garbage", b"\xff", b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN CERTIFICATE-----\nbroken", b"x" * 262145])
def test_invalid_ca_rejected_before_dns(profile, tmp_path, monkeypatch, pem):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(pem)
    monkeypatch.setattr(module, "resolve_pinned", lambda *args: pytest.fail("Invalid CA reached DNS"))
    with pytest.raises(ValueError):
        module.inspect_service(profile[0], "https://localhost/", authorized=True, ca_file=ca)


def test_unsafe_mixed_dns_answer_refuses_entire_host(profile, monkeypatch):
    # Default profile (non-lab) must reject a host with even one private answer.
    profile[1](lab_mode=False, allow_private_network=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    monkeypatch.setattr(socket, "socket", lambda *a: pytest.fail("Unsafe DNS caused a connection"))
    with pytest.raises(ValueError, match="Unsafe DNS"):
        module.inspect_service(profile[0], "https://localhost/", authorized=True)


@pytest.mark.parametrize("error,outcome", [(ConnectionRefusedError(), "refused"), (TimeoutError(), "timeout"),
    (OSError("private-address secret"), "unreachable")])
def test_transport_failures_have_no_retry_or_private_exception(profile, monkeypatch, error, outcome):
    calls = []
    class FailingSocket:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, value):
            assert 0 < value <= 5
        def connect(self, address):
            calls.append(address)
            raise error
    monkeypatch.setattr(module, "resolve_pinned", lambda *a: "127.0.0.1")
    monkeypatch.setattr(socket, "socket", lambda *a: FailingSocket())
    report = module.inspect_service(profile[0], "https://localhost/", authorized=True)
    assert calls == [("127.0.0.1", 443)]
    assert report["outcome"] == outcome
    assert report["certificate_and_hostname_verified"] is None
    assert "private-address" not in json.dumps(report)


def test_cli_existing_output_prevents_network(profile, tmp_path, monkeypatch):
    output = tmp_path / "existing.json"
    output.write_text("retain")
    monkeypatch.setattr(module, "inspect_service", lambda *a, **k: pytest.fail("Existing output reached network"))
    with pytest.raises(FileExistsError):
        main(["tls-service-inspect", "--profile", str(profile[0]), "--target", "https://localhost/",
              "--authorized", "--out", str(output)])
    assert output.read_text() == "retain"


def test_connect_budget_exhaustion_prevents_tls_handshake(profile, monkeypatch):
    times = iter([100.0, 106.0])
    closed = []
    class SlowSocket:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            closed.append(True)
        def settimeout(self, value):
            assert value == 5
        def connect(self, address):
            assert address == ("127.0.0.1", 443)
    monkeypatch.setattr(module, "resolve_pinned", lambda *a: "127.0.0.1")
    monkeypatch.setattr(socket, "socket", lambda *a: SlowSocket())
    monkeypatch.setattr(module.time, "monotonic", lambda: next(times))
    report = module.inspect_service(profile[0], "https://localhost/", authorized=True)
    assert report["outcome"] == "timeout" and closed == [True]


def test_numeric_dial_keeps_original_hostname_for_verification(profile, monkeypatch):
    resolved, connected, names = [], [], []
    class RawSocket:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, value):
            assert 0 < value <= 5
        def connect(self, address):
            connected.append(address)
    class Context:
        verify_flags = 0
        def load_default_certs(self):
            pass
        def set_alpn_protocols(self, protocols):
            assert protocols == ["h2", "http/1.1"]
        def wrap_socket(self, sock, *, server_hostname):
            names.append(server_hostname)
            raise ssl.SSLError("private handshake error")
    def resolve(*args):
        resolved.append(True)
        return "8.8.8.8"
    monkeypatch.setattr(module, "resolve_pinned", resolve)
    monkeypatch.setattr(socket, "socket", lambda *a: RawSocket())
    monkeypatch.setattr(ssl, "SSLContext", lambda *a: Context())
    report = module.inspect_service(profile[0], "https://localhost/", authorized=True)
    assert resolved == [True] and connected == [("8.8.8.8", 443)] and names == ["localhost"]
    assert report["outcome"] == "tls-error" and "private handshake error" not in json.dumps(report)


def test_cli_unapproved_output_prevents_network(profile, tmp_path, monkeypatch):
    monkeypatch.setattr(module, "inspect_service", lambda *a, **k: pytest.fail("Unapproved output reached network"))
    with pytest.raises(ValueError):
        main(["tls-service-inspect", "--profile", str(profile[0]), "--target", "https://localhost/",
              "--authorized", "--out", str(tmp_path.parent / "outside-receipt.json")])


def test_cli_real_verified_receipt(profile, certificates, tmp_path, monkeypatch):
    ca, output = tmp_path / "ca.pem", tmp_path / "receipt.json"
    keylog = tmp_path / "session-secrets.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    ca.write_bytes(certificates["ca"])
    with server(certificates) as (port, _, _):
        profile[1](allowed_ports=[port])
        main(["tls-service-inspect", "--profile", str(profile[0]), "--target", f"https://localhost:{port}/",
              "--authorized", "--ca-file", str(ca), "--out", str(output)])
    result = json.loads(output.read_text())
    assert result["outcome"] == "verified" and result["trust_source"] == "owner-supplied-ca"
    assert result["ca_bundle_sha256"] == hashlib.sha256(ca.read_bytes()).hexdigest()
    assert not keylog.exists()
