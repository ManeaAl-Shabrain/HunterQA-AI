"""Code/PKCE/state/signature/role boundaries against an owned OIDC provider."""
import base64
import hashlib
import json
import os
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from hunterqa import create_app, operator_oidc as oidc, operator_store as store
from hunterqa.oidc_tokens import pkce_challenge
from hunterqa.engagement import utcnow

BASE = "http://localhost:8080"
ISSUER = "https://idp.fixture.test/tenant"
PASSWORD = "Owned-local-password-123!"


@pytest.fixture(scope="module")
def signing():
    jwt = pytest.importorskip("jwt")
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="owned-key", use="sig", alg="RS256", x5c=["ignored-certificate-metadata"], issuer="not-an-issuer-anchor")
    return key, jwk


@pytest.fixture
def sso(tmp_path, monkeypatch, fake_service, signing):
    control, cases = tmp_path / "control", tmp_path / "cases"
    control.mkdir(mode=0o700)
    cases.mkdir()
    monkeypatch.setenv("HUNTERQA_OPERATOR_ROOT", str(control))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(cases))
    monkeypatch.delenv("HUNTERQA_WORKSPACE_CONFIG", raising=False)
    monkeypatch.delenv("HUNTERQA_OIDC_CONFIG", raising=False)
    monkeypatch.delenv("HUNTERQA_OPERATOR_SESSION_KEY_FILE", raising=False)
    monkeypatch.setattr(store, "HASH_METHOD", "pbkdf2:sha256:1000")
    database = control / "operators.sqlite3"
    store.initialize(database, "admin", PASSWORD, authorized=True)
    store.add_operator(database, "viewer", "viewer", PASSWORD, authorized=True)
    config = {"schema_version": 1, "issuer": ISSUER, "client_id": "owned-client",
        "authorization_endpoint": "https://idp.fixture.test/authorize", "token_endpoint": "https://idp.fixture.test/token",
        "jwks_uri": "https://idp.fixture.test/keys", "redirect_uri": BASE + "/oidc/callback",
        "client_secret_file": None, "bindings": [{"subject": "subject-viewer", "username": "viewer"}],
        "local_password_login": False, "allow_private_provider": False}
    path = control / "oidc.json"
    path.write_text(json.dumps(config))
    if os.name == "posix":
        path.chmod(0o600)
    trace = SimpleNamespace(nonce=None, challenge=None, claims={}, actions=[], fail=None, wrong_key=False)
    def transport(settings, action, body=None):
        trace.actions.append(action)
        if trace.fail == action:
            raise OSError("PRIVATE_PROVIDER_ERROR")
        if action == "jwks":
            return {"keys": [{**signing[1], "kid": "wrong-key"} if trace.wrong_key else signing[1]]}
        params = parse_qs(body.decode(), strict_parsing=True)
        assert params["grant_type"] == ["authorization_code"] and params["redirect_uri"] == [config["redirect_uri"]]
        assert pkce_challenge(params["code_verifier"][0]) == trace.challenge
        assert params["client_id"] == ["owned-client"]
        now = int(time.time())
        claims = {"iss": ISSUER, "sub": "subject-viewer", "aud": "owned-client", "iat": now, "exp": now + 300,
            "nonce": trace.nonce, "roles": ["admin"], "email": "admin@attacker.invalid", **trace.claims}
        import jwt
        return {"id_token": jwt.encode(claims, signing[0], algorithm="RS256", headers={"kid": "owned-key"}),
            "access_token": "owned-access-token", "token_type": "Bearer"}
    app_config = {"TESTING": True, "SECRET_KEY": "Owned-session-secret-" + "x" * 48,
        "DATABASE": str(tmp_path / "dashboard.sqlite3"), "APPROVED_ROOTS": [str(cases)],
        "OPERATOR_DATABASE": str(database), "OIDC_CONFIG": str(path), "SCAN_SERVICE": fake_service,
        "OIDC_TRANSPORT": transport}
    app = create_app(app_config)
    return SimpleNamespace(app=app, database=database, config=config, path=path, trace=trace,
        app_config=app_config, transport=transport, control=control, signing=signing)


def begin(sso, client):
    client.get("/login", base_url=BASE)
    with client.session_transaction(base_url=BASE) as session:
        csrf = session["csrf_token"]
    response = client.post("/oidc/start", data={"csrf_token": csrf}, base_url=BASE)
    assert response.status_code == 302
    args = parse_qs(urlsplit(response.location).query)
    assert args["scope"] == ["openid"] and args["code_challenge_method"] == ["S256"]
    assert "client_secret" not in args and "code_verifier" not in args
    sso.trace.nonce, sso.trace.challenge = args["nonce"][0], args["code_challenge"][0]
    return args["state"][0]


def finish(sso, client, state, **extra):
    return client.get("/oidc/callback?" + urlencode({"state": state, "code": "owned-code", **extra}), base_url=BASE)


def test_verified_subject_uses_local_role_ignores_email_roles_and_rotates_session(sso):
    client = sso.app.test_client()
    state = begin(sso, client)
    with client.session_transaction(base_url=BASE) as old:
        previous_csrf = old["csrf_token"]
    response = finish(sso, client, state)
    assert response.status_code == 302 and sso.trace.actions == ["token", "jwks"]
    assert client.get("/projects", base_url=BASE).status_code == 200
    assert client.get("/operators", base_url=BASE).status_code == 403
    with client.session_transaction(base_url=BASE) as session:
        assert "oidc_browser" not in session and "nonce" not in session and "verifier" not in session
        assert session["csrf_token"] != previous_csrf
        csrf = session["csrf_token"]
    assert client.post("/projects", data={"csrf_token": csrf}, base_url=BASE).status_code == 403
    assert client.post("/logout", data={"csrf_token": csrf}, base_url=BASE).status_code == 302
    assert client.get("/api/scans/1/status", base_url=BASE).status_code == 401


@pytest.mark.parametrize("claims", [{"iss": "https://other.invalid"}, {"sub": "unmapped"}, {"aud": "other-client"},
    {"nonce": "wrong-nonce"}, {"exp": 1}, {"iat": 1}, {"iat": True}, {"aud": ["owned-client", "other"], "azp": "other"},
    {"at_hash": "wrong-binding"}, {"nbf": 9999999999}])
def test_signature_claim_subject_and_access_token_binding_fail_closed(sso, claims):
    client = sso.app.test_client()
    state = begin(sso, client)
    sso.trace.claims.update(claims)
    response = finish(sso, client, state)
    assert response.status_code == 401 and b"Single sign-on failed" in response.data
    assert client.get("/api/scans/1/status", base_url=BASE).status_code == 401
    assert b"PRIVATE_PROVIDER" not in response.data and b"owned-code" not in response.data


def test_correct_at_hash_and_current_key_rotation_supported(sso):
    client = sso.app.test_client()
    state = begin(sso, client)
    sso.trace.claims["at_hash"] = base64.urlsafe_b64encode(hashlib.sha256(b"owned-access-token").digest()[:16]).decode().rstrip("=")
    assert finish(sso, client, state).status_code == 302


def test_callback_replay_has_no_second_provider_request(sso):
    client = sso.app.test_client()
    state = begin(sso, client)
    assert finish(sso, client, state).status_code == 302
    assert finish(sso, client, state).status_code == 401
    assert sso.trace.actions == ["token", "jwks"]


def test_parallel_callbacks_consume_state_atomically(sso):
    first, other = sso.app.test_client(), sso.app.test_client()
    state = begin(sso, first)
    with first.session_transaction(base_url=BASE) as session:
        shared = dict(session)
    with other.session_transaction(base_url=BASE) as session:
        session.update(shared)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda client: finish(sso, client, state).status_code, (first, other)))
    assert sorted(results) == [302, 401] and sso.trace.actions == ["token", "jwks"]


def test_state_is_bound_to_initiating_browser_and_duplicate_state_rejected(sso):
    first, other = sso.app.test_client(), sso.app.test_client()
    state = begin(sso, first)
    assert finish(sso, other, state).status_code == 401 and not sso.trace.actions
    assert first.get("/oidc/callback?" + urlencode([("state", state), ("state", state), ("code", "owned-code")]), base_url=BASE).status_code == 401
    assert not sso.trace.actions
    assert finish(sso, first, state).status_code == 302


@pytest.mark.parametrize("failure", ["token", "jwks", "key", "expired", "disabled", "config-change", "provider-error", "issuer-response"])
def test_failed_or_changed_login_attempt_does_not_create_session(sso, failure):
    client = sso.app.test_client()
    state = begin(sso, client)
    args = {}
    if failure in ("token", "jwks"):
        sso.trace.fail = failure
    elif failure == "key":
        sso.trace.wrong_key = True
    elif failure == "expired":
        with store.database(sso.database, write=True) as db:
            db.execute("UPDATE operator_oidc_attempts SET created=0,expires=300")
    elif failure == "disabled":
        store.update_operator(sso.database, "viewer", active=False, authorized=True)
    elif failure == "config-change":
        sso.config["client_id"] = "changed-client"
        sso.path.write_text(json.dumps(sso.config))
    elif failure == "provider-error":
        args = {"error": "access_denied", "error_description": "PRIVATE_PROVIDER_ERROR"}
    else:
        args = {"iss": "https://other.invalid"}
    response = finish(sso, client, state, **args)
    assert response.status_code == 401 and b"PRIVATE_PROVIDER_ERROR" not in response.data
    assert client.get("/api/scans/1/status", base_url=BASE).status_code == 401


def test_local_account_revocation_invalidates_federated_session_on_next_request(sso):
    client = sso.app.test_client()
    assert finish(sso, client, begin(sso, client)).status_code == 302
    store.update_operator(sso.database, "viewer", active=False, authorized=True)
    assert client.get("/api/scans/1/status", base_url=BASE).status_code == 401


def test_ssO_start_csrf_host_and_rate_limits_and_password_fallback(sso):
    client = sso.app.test_client()
    assert client.post("/oidc/start", base_url=BASE).status_code == 400
    client.get("/login", base_url=BASE)
    with client.session_transaction(base_url=BASE) as session:
        csrf = session["csrf_token"]
    assert client.post("/oidc/start", data={"csrf_token": csrf}, base_url="http://localhost:8081").status_code == 400
    assert client.post("/login", data={"csrf_token": csrf, "username": "viewer", "password": PASSWORD}, base_url=BASE).status_code == 403
    for _ in range(20):
        assert client.post("/oidc/start", data={"csrf_token": csrf}, base_url=BASE).status_code == 302
    assert client.post("/oidc/start", data={"csrf_token": csrf}, base_url=BASE).status_code == 429


def test_missing_provider_configuration_cannot_downgrade_existing_dashboard(sso):
    config = {**sso.app_config, "OIDC_CONFIG": ""}
    with pytest.raises(ValueError, match="Restore"):
        create_app(config)


@pytest.mark.parametrize("field,value", [("issuer", "http://idp.invalid"), ("token_endpoint", "https://u:p@idp.invalid/token"),
    ("jwks_uri", "https://idp.invalid/keys?next=evil"), ("redirect_uri", "https://evil.invalid/oidc/callback"),
    ("redirect_uri", "http://localhost:8080/elsewhere"), ("bindings", [{"subject": "sub", "username": "absent"}]),
    ("bindings", [{"subject": "x", "username": "viewer"}] * 2), ("local_password_login", "false")])
def test_provider_configuration_rejected_at_startup(sso, field, value):
    sso.config[field] = value
    sso.path.write_text(json.dumps(sso.config))
    with pytest.raises(ValueError):
        create_app(sso.app_config)


def test_custom_transport_not_accepted_in_non_test_deployment(sso):
    with pytest.raises(ValueError, match="owned tests"):
        create_app({**sso.app_config, "TESTING": False})


def test_client_secret_only_in_backchannel_and_different_workspace_identity_rejected(sso):
    secret = sso.control / "client.secret"
    secret.write_text("owned-provider-client-secret-0123456789\n")
    if os.name == "posix":
        secret.chmod(0o600)
    sso.config["client_secret_file"] = str(secret)
    sso.path.write_text(json.dumps(sso.config))
    seen = []
    def transport(config, action, body=None):
        if body:
            seen.append(parse_qs(body.decode())["client_secret"])
        return sso.transport(config, action, body)
    sso.app = create_app({**sso.app_config, "OIDC_TRANSPORT": transport})
    client = sso.app.test_client()
    state = begin(sso, client)
    assert finish(sso, client, state).status_code == 302
    assert seen == [["owned-provider-client-secret-0123456789"]]
    with client.session_transaction(base_url=BASE) as session:
        assert "owned-provider-client-secret" not in json.dumps(dict(session))


def test_jwks_certificate_metadata_does_not_supply_trust_or_network_targets(signing):
    keys = oidc.signing_keys({"keys": [{**signing[1], "x5u": "http://169.254.169.254/never", "jku": "https://evil.invalid"},
        {"kty": "EC", "kid": "other"}, {"kty": "RSA", "use": "enc", "kid": "encryption"}]})
    assert len(keys["keys"]) == 1 and "x5u" not in keys["keys"][0] and "x5c" not in keys["keys"][0]


@contextmanager
def owned_https_provider(sso, tmp_path, monkeypatch, fault=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    now = utcnow()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned OIDC CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.fixture.test")]))
        .issuer_name(name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("idp.fixture.test")]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256()))
    cert, private_key = tmp_path / "idp.pem", tmp_path / "idp-key.pem"
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    private_key.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    observed, errors = [], []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.reply("token", self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        def do_GET(self):
            if self.path.startswith("/authorize?"):
                values = parse_qs(urlsplit(self.path).query)
                sso.trace.nonce, sso.trace.challenge = values["nonce"][0], values["code_challenge"][0]
                self.send_response(302)
                self.send_header("Location", sso.config["redirect_uri"] + "?" + urlencode({"state": values["state"][0], "code": "owned-code", "iss": ISSUER}))
                self.end_headers()
                return
            self.reply("jwks")
        def reply(self, action, body=None):
            try:
                observed.append((self.command, self.path, self.headers.get("Host")))
                assert self.path == ("/token" if action == "token" else "/keys")
                if action == "token" and fault:
                    data = b"x" * 65537 if fault == "oversized" else b"{}"
                else:
                    data = json.dumps(sso.transport(sso.config, action, body)).encode()
                self.send_response(302 if fault == "redirect" else 200)
                self.send_header("Content-Length", str(len(data)))
                if fault == "redirect":
                    self.send_header("Location", "https://evil.invalid/never-follow")
                if fault == "gzip":
                    self.send_header("Content-Encoding", "gzip")
                self.end_headers()
                self.wfile.write(data)
            except (OSError, ssl.SSLError):
                pass
            except Exception as exc:
                errors.append(type(exc).__name__)
        def log_message(self, *args):
            pass
    service = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, private_key)
    service.socket = tls.wrap_socket(service.socket, server_side=True)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    original = ssl.SSLContext.load_default_certs
    def trust(ctx, *args, **kwargs):
        original(ctx, *args, **kwargs)
        ctx.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM).decode())
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", trust)
    monkeypatch.setattr(oidc, "resolve_pinned", lambda *args: "8.8.8.8")
    monkeypatch.setattr(oidc, "_dial", lambda ip, port, end: socket.create_connection(("127.0.0.1", service.server_port), timeout=5))
    try:
        spki = leaf_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        yield SimpleNamespace(observed=observed, port=service.server_port, spki=base64.b64encode(hashlib.sha256(spki).digest()).decode())
    finally:
        service.shutdown()
        service.server_close()
        thread.join(5)
        assert not thread.is_alive() and not errors


@pytest.mark.parametrize("fault", [None, "redirect", "gzip", "oversized"])
def test_native_https_provider_code_exchange_and_rotation_material(sso, tmp_path, monkeypatch, fault):
    sso.app = create_app({**sso.app_config, "OIDC_TRANSPORT": None})
    client = sso.app.test_client()
    state = begin(sso, client)
    with owned_https_provider(sso, tmp_path, monkeypatch, fault) as provider:
        response = finish(sso, client, state)
    assert response.status_code == (302 if fault is None else 401)
    assert [row[0] for row in provider.observed] == (["POST", "GET"] if fault is None else ["POST"])
    assert all(row[2] == "idp.fixture.test" for row in provider.observed)


@pytest.mark.parametrize("private_allowed", [False, True])
def test_metadata_or_mixed_dns_rejected_before_provider_connection(sso, monkeypatch, private_allowed):
    config = {**sso.config, "allow_private_provider": private_allowed}
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))])
    monkeypatch.setattr(oidc, "_Connection", lambda *a: pytest.fail("Unsafe DNS reached provider transport"))
    with pytest.raises(ValueError, match="Unsafe DNS"):
        oidc.provider_request(config, "jwks")


def test_provider_tls_hostname_mismatch_sends_no_code_or_secret(sso, tmp_path, monkeypatch):
    sso.config["token_endpoint"] = "https://wrong.fixture.test/token"
    sso.path.write_text(json.dumps(sso.config))
    sso.app = create_app({**sso.app_config, "OIDC_TRANSPORT": None})
    client = sso.app.test_client()
    state = begin(sso, client)
    with owned_https_provider(sso, tmp_path, monkeypatch) as provider:
        assert finish(sso, client, state).status_code == 401
    assert not provider.observed and not sso.trace.actions


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Opt-in real Chromium OIDC redirect/cookie test")
def test_real_browser_cross_site_oidc_callback_and_logout(sso, tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright
    from werkzeug.serving import make_server
    service = make_server("127.0.0.1", 0, sso.app, threaded=True)
    base = "http://127.0.0.1:" + str(service.server_port)
    sso.config["redirect_uri"] = base + "/oidc/callback"
    sso.path.write_text(json.dumps(sso.config))
    sso.app = create_app({**sso.app_config, "OIDC_TRANSPORT": None})
    service.app = sso.app
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        with owned_https_provider(sso, tmp_path, monkeypatch) as provider:
            sso.config["authorization_endpoint"] = "https://idp.fixture.test:" + str(provider.port) + "/authorize"
            sso.path.write_text(json.dumps(sso.config))
            service.app = create_app({**sso.app_config, "OIDC_TRANSPORT": None})
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(args=["--host-resolver-rules=MAP idp.fixture.test 127.0.0.1",
                    "--ignore-certificate-errors-spki-list=" + provider.spki])
                context = browser.new_context()
                seen = []
                page = context.new_page()
                page.on("request", lambda req: seen.append(req.url) if "/authorize?" in req.url else None)
                diagnostics = []
                page.on("console", lambda message: diagnostics.append(message.text))
                page.on("requestfailed", lambda req: diagnostics.append(req.url + ":" + str(req.failure)))
                page.goto(base + "/login")
                page.get_by_role("button", name="Continue with single sign-on").click()
                try:
                    page.wait_for_url(base + "/", timeout=10000)
                except Exception:
                    raise AssertionError({"url": page.url, "authorize_seen": len(seen), "diagnostics": diagnostics}) from None
                assert "Signed in as" in page.content() and "viewer" in page.content()
                assert "owned-code" not in page.url and len(seen) == 1
                page.locator("[data-operator-logout] button").click()
                page.wait_for_url(base + "/login")
                assert [row[0] for row in provider.observed] == ["POST", "GET"]
                context.close()
                browser.close()
    finally:
        service.shutdown()
        service.server_close()
        thread.join(5)
        assert not thread.is_alive()
