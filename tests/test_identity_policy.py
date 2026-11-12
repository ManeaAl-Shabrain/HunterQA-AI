"""Owned authentication contracts: these are not live Google/Entra acceptance."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from types import SimpleNamespace
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from hunterqa import create_app, identity_policy as policy, operator_store as store, workspace
from hunterqa.oidc_tokens import pkce_challenge
from tests import test_workspaces as ws
from tests import test_operator_sso

BASE = "http://localhost:8080"
SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
TENANT = "11111111-2222-4333-8444-555555555555"


@pytest.fixture(scope="module")
def signing():
    return test_operator_sso.signing.__wrapped__()


@pytest.fixture
def identity(tmp_path, monkeypatch, signing):
    spaces = ws.spaces.__wrapped__(tmp_path, monkeypatch)
    config = spaces[2][0]
    private, database = config.parent, config.parent / "operators.sqlite3"
    store.add_operator(database, "viewer", "viewer", ws.PASSWORD, authorized=True)
    result = policy.setup(config, BASE, authorized=True)
    path = private / "identity.json"
    data = json.loads(path.read_text())
    for name in ("google", "entra"):
        secret = private / (name + ".secret")
        secret.write_text("Owned-provider-client-secret-" + name)
        if os.name == "posix":
            secret.chmod(0o600)
        data["providers"][name] = {"enabled": True, "client_id": "owned-client-" + name,
            "client_secret_file": str(secret), "bindings": [{"subject": "approved-" + name, "username": "admin"}]}
        if name == "entra":
            data["providers"][name]["tenant_id"] = TENANT
    path.write_text(json.dumps(data))
    policy.enroll(database, result["key_file"], "admin", SEED, authorized=True)
    monkeypatch.setattr(workspace, "_ACTIVE", None)
    trace = SimpleNamespace(actions=[], claims={}, args={}, fail=False)

    def transport(settings, action, body=None):
        trace.actions.append(action)
        if trace.fail:
            raise OSError("PRIVATE_PROVIDER_FAILURE")
        if action == "jwks":
            return {"keys": [signing[1]]}
        params = parse_qs(body.decode(), strict_parsing=True)
        assert params["grant_type"] == ["authorization_code"]
        assert params["redirect_uri"] == [settings["redirect_uri"]]
        assert params["client_secret"] == [settings["secret"]]
        assert pkce_challenge(params["code_verifier"][0]) == trace.args["code_challenge"][0]
        name = "entra" if settings["tenant"] else "google"
        now = int(time.time())
        claims = {"iss": settings["issuer"], "aud": settings["client_id"], "sub": "approved-" + name,
            "iat": now, "exp": now + 300, "nonce": trace.args["nonce"][0], "roles": ["admin"],
            "email": "admin@untrusted.invalid", **({"tid": TENANT} if name == "entra" else {}), **trace.claims}
        import jwt
        return {"id_token": jwt.encode(claims, signing[0], algorithm="RS256", headers={"kid": "owned-key"})}

    options = {"WORKSPACE_CONFIG": str(config), "TESTING": True, "IDENTITY_TRANSPORT": transport}
    app = create_app(options)
    return SimpleNamespace(app=app, options=options, spaces=spaces, config=config, path=path,
        data=data, database=database, key=private / "auth.key", trace=trace, selected=policy.load(path))


def csrf(client):
    client.get("/login", base_url=BASE)
    with client.session_transaction(base_url=BASE) as session:
        return session["csrf_token"]


def local(identity, client, username="admin"):
    return client.post("/login", base_url=BASE, data={"username": username, "password": ws.PASSWORD, "csrf_token": csrf(client)})


def factor(client, code=None):
    client.get("/auth/mfa", base_url=BASE)
    with client.session_transaction(base_url=BASE) as session:
        token = session["csrf_token"]
    return client.post("/auth/mfa", base_url=BASE, data={"csrf_token": token, "code": code or policy.totp(SEED)})


def start(identity, client, name):
    response = client.post("/auth/" + name + "/start", base_url=BASE, data={"csrf_token": csrf(client)})
    assert response.status_code == 302
    args = parse_qs(urlsplit(response.location).query)
    assert args["scope"] == ["openid"] and args["code_challenge_method"] == ["S256"]
    assert not {"client_secret", "code_verifier"} & set(args)
    identity.trace.args = args
    return args["state"][0]


def callback(client, name, state):
    return client.get("/auth/" + name + "/callback?" + urlencode({"state": state, "code": "owned-code"}), base_url=BASE)


def test_rfc6238_vectors_and_replay_window():
    assert base64.b32decode(SEED) == b"12345678901234567890"
    for when, expected in [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (20000000000, "65353130")]:
        assert policy.totp(SEED, when, digits=8) == expected
    assert policy.matched_step(SEED, "287082", 59) == 1
    assert policy.matched_step(SEED, "287082", 59, 1) is None
    for code in ("287082 ", "２８７０８２", "94287082", None):
        assert policy.matched_step(SEED, code, 59) is None


def test_local_admin_has_no_access_or_full_session_before_mfa(identity):
    client = identity.app.test_client()
    response = local(identity, client)
    assert response.status_code == 302 and response.location.endswith("/auth/mfa")
    assert client.get("/api/scans/1/status", base_url=BASE).status_code == 401
    with client.session_transaction(base_url=BASE) as session:
        assert "identity_grant" in session and "operator_session" not in session
        assert SEED not in str(dict(session))
    with store.database(identity.database) as db:
        assert db.execute("SELECT COUNT(*) FROM operator_sessions").fetchone()[0] == 0
        assert SEED not in db.execute("SELECT secret_cipher FROM operator_factors").fetchone()[0]
    assert factor(client, "12345").status_code == 401
    assert factor(client).status_code == 302
    assert client.get("/operators", base_url=BASE).status_code == 200
    with client.session_transaction(base_url=BASE) as session:
        assert "identity_grant" not in session and "operator_session" in session
    assert SEED.encode() not in identity.database.read_bytes()
    assert store.audit_status(identity.database)["events"] > 0


def test_viewer_preserves_local_role_and_no_signup(identity):
    client = identity.app.test_client()
    assert local(identity, client, "viewer").status_code == 302
    assert client.get("/projects", base_url=BASE).status_code == 200
    assert client.get("/operators", base_url=BASE).status_code == 403
    assert client.post("/projects", base_url=BASE, data={"csrf_token": csrf(client)}).status_code == 403
    assert client.get("/register", base_url=BASE).status_code == 404


@pytest.mark.parametrize("name", ["google", "entra"])
def test_both_providers_bind_same_approved_account_and_require_mfa(identity, name):
    client = identity.app.test_client()
    state = start(identity, client, name)
    with store.database(identity.database) as db:
        attempt = db.execute("SELECT * FROM identity_attempts").fetchone()
        assert identity.trace.args["nonce"][0] not in attempt["nonce_cipher"]
        assert policy.unseal(identity.selected["key"], name + ":nonce", attempt["nonce_cipher"]) == identity.trace.args["nonce"][0]
    assert callback(client, name, state).location.endswith("/auth/mfa")
    assert client.get("/api/scans/1/status", base_url=BASE).status_code == 401
    assert factor(client).status_code == 302
    with client.session_transaction(base_url=BASE) as session:
        user = store.session_operator(identity.database, session["operator_session"], session["operator_instance"])
    assert user["username"] == "admin"
    assert identity.trace.actions == ["token", "jwks"]
    assert callback(client, name, state).status_code == 401
    assert identity.trace.actions == ["token", "jwks"]


def test_documented_google_bare_issuer_is_verified(identity):
    client = identity.app.test_client()
    state = start(identity, client, "google")
    identity.trace.claims["iss"] = "accounts.google.com"
    assert callback(client, "google", state).location.endswith("/auth/mfa")


@pytest.mark.parametrize("name,claims", [("google", {"iss": "https://attacker.invalid"}),
    ("google", {"sub": "unapproved"}), ("google", {"aud": "other-client"}), ("google", {"nonce": "wrong"}),
    ("google", {"exp": 1}), ("google", {"iat": 1}), ("google", {"at_hash": "wrong"}),
    ("entra", {"tid": "other-tenant"}), ("entra", {"tid": None}),
    ("entra", {"iss": "https://login.microsoftonline.com/common/v2.0"})])
def test_untrusted_identities_never_receive_session_or_account(identity, name, claims):
    client = identity.app.test_client()
    state = start(identity, client, name)
    identity.trace.claims.update(claims)
    assert callback(client, name, state).status_code == 401
    assert client.get("/api/scans/1/status", base_url=BASE).status_code == 401
    with store.database(identity.database) as db:
        assert db.execute("SELECT COUNT(*) FROM operators").fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM operator_sessions").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM identity_grants").fetchone()[0] == 0


def test_provider_state_is_bound_to_browser_and_provider(identity):
    client = identity.app.test_client()
    state = start(identity, client, "google")
    assert callback(client, "entra", state).status_code == 401
    assert callback(identity.app.test_client(), "google", state).status_code == 401
    assert not identity.trace.actions
    assert callback(client, "google", state).location.endswith("/auth/mfa")


def test_provider_outage_no_secret_leak_or_password_fallback(identity):
    client = identity.app.test_client()
    state = start(identity, client, "entra")
    identity.trace.fail = True
    result = callback(client, "entra", state)
    assert result.status_code == 401 and b"PRIVATE_PROVIDER" not in result.data
    assert b"owned-code" not in result.data
    assert callback(client, "entra", state).status_code == 401
    assert identity.trace.actions == ["token"]


@pytest.mark.parametrize("name", ["google", "entra"])
def test_provider_admin_claim_never_elevates_local_viewer(identity, name):
    identity.data["providers"][name]["bindings"][0]["username"] = "viewer"
    identity.path.write_text(json.dumps(identity.data))
    app = create_app(identity.options)
    client = app.test_client()
    state = start(identity, client, name)
    assert callback(client, name, state).location.endswith("/")
    assert client.get("/projects", base_url=BASE).status_code == 200
    assert client.get("/operators", base_url=BASE).status_code == 403
    assert client.post("/projects", base_url=BASE, data={"csrf_token": csrf(client)}).status_code == 403


def test_policy_can_require_mfa_for_all_roles(identity):
    identity.data["mfa_roles"] = ["admin", "analyst", "viewer"]
    identity.path.write_text(json.dumps(identity.data))
    with pytest.raises(ValueError, match="Enroll MFA"):
        create_app(identity.options)
    policy.enroll(identity.database, identity.key, "viewer", SEED, authorized=True)
    client = create_app(identity.options).test_client()
    assert local(identity, client, "viewer").location.endswith("/auth/mfa")
    assert factor(client).status_code == 302


def test_cancel_challenge_and_grant_throttling(identity):
    client = identity.app.test_client()
    local(identity, client)
    token = csrf(client)
    assert client.post("/auth/mfa", base_url=BASE, data={"csrf_token": token, "cancel": "yes"}).location.endswith("/login")
    assert client.get("/api/scans/1/status", base_url=BASE).status_code == 401
    with store.database(identity.database) as db:
        assert db.execute("SELECT COUNT(*) FROM identity_grants").fetchone()[0] == 0
    for _ in range(9):
        assert policy.begin(identity.database, identity.selected, "admin", "local")
    assert policy.begin(identity.database, identity.selected, "admin", "local") is None


@pytest.mark.parametrize("change", ["disable", "password", "role", "expiry", "policy", "instance"])
def test_pending_factor_invalidated_by_identity_changes(identity, change):
    grant = policy.begin(identity.database, identity.selected, "admin", "local")[0]
    if change in {"disable", "role"}:
        store.add_operator(identity.database, "second-admin", "admin", ws.PASSWORD, authorized=True)
    if change == "disable":
        store.update_operator(identity.database, "admin", active=False, authorized=True)
    elif change == "password":
        store.update_operator(identity.database, "admin", password="A-different-valid-password-123!", authorized=True)
    elif change == "role":
        store.update_operator(identity.database, "admin", role="viewer", authorized=True)
    elif change == "policy":
        identity.selected["fingerprint"] = "different"
    else:
        with store.database(identity.database, write=True) as db:
            if change == "expiry":
                db.execute("UPDATE identity_grants SET expires=0")
            else:
                db.execute("UPDATE identity SET instance='changed'")
    assert policy.finish(identity.database, identity.selected, grant, policy.totp(SEED)) is None


def test_factor_replay_attempt_cap_and_parallel_consumption(identity):
    grant = policy.begin(identity.database, identity.selected, "admin", "local")[0]
    code = policy.totp(SEED)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: policy.finish(identity.database, identity.selected, grant, code), range(2)))
    assert sum(value is not None for value in results) == 1
    other = policy.begin(identity.database, identity.selected, "admin", "google")[0]
    assert policy.finish(identity.database, identity.selected, other, code) is None
    bad = "000000" if code != "000000" else "111111"
    for _ in range(5):
        assert policy.finish(identity.database, identity.selected, other, bad) is None
    assert policy.finish(identity.database, identity.selected, other, policy.totp(SEED, time.time() + 30)) is None


def test_policy_changes_fail_closed_and_require_restart(identity, monkeypatch):
    client = identity.app.test_client()
    identity.data["local_enabled"] = False
    identity.path.write_text(json.dumps(identity.data))
    assert client.get("/login", base_url=BASE).status_code == 503
    app = create_app(identity.options)
    client = app.test_client()
    assert local(identity, client).status_code == 403
    identity.data["providers"]["google"] = {"enabled": False}
    identity.path.write_text(json.dumps(identity.data))
    app = create_app(identity.options)
    client = app.test_client()
    assert client.post("/auth/google/start", base_url=BASE, data={"csrf_token": csrf(client)}).status_code == 404
    assert client.post("/auth/entra/start", base_url=BASE, data={"csrf_token": csrf(client)}).status_code == 302
    config = json.loads(identity.config.read_text())
    config.pop("auth_config")
    identity.config.write_text(json.dumps(config))
    monkeypatch.setattr(workspace, "_ACTIVE", None)
    with pytest.raises(ValueError, match="required unified"):
        create_app(identity.options)


def test_missing_factor_or_unapproved_binding_blocks_startup(identity):
    with store.database(identity.database, write=True) as db:
        db.execute("DELETE FROM operator_factors")
    with pytest.raises(ValueError, match="Enroll MFA"):
        create_app(identity.options)


def test_csrf_and_enrollment_revoke_prior_sessions(identity):
    client = identity.app.test_client()
    assert client.post("/auth/google/start", base_url=BASE).status_code == 400
    assert local(identity, client).status_code == 302
    assert client.post("/auth/mfa", base_url=BASE, data={"code": policy.totp(SEED)}).status_code == 400
    assert factor(client).status_code == 302
    policy.enroll(identity.database, identity.key, "admin", SEED, authorized=True)
    assert client.get("/api/scans/1/status", base_url=BASE).status_code == 401


def test_offline_local_never_calls_provider(identity):
    identity.data["providers"] = {name: {"enabled": False} for name in ("google", "entra")}
    identity.path.write_text(json.dumps(identity.data))
    app = create_app(identity.options)
    identity.trace.fail = True
    client = app.test_client()
    assert local(identity, client).location.endswith("/auth/mfa")
    assert factor(client).status_code == 302
    assert identity.trace.actions == []


def test_custom_transport_rejected_outside_test_mode(identity):
    with pytest.raises(ValueError, match="owned tests"):
        create_app({**identity.options, "TESTING": False})


def test_unified_backup_restores_dependencies_rotates_key_and_requires_reenrollment(identity, tmp_path, monkeypatch):
    from hunterqa import workspace_backup as recovery
    directory = tmp_path / "backups"
    directory.mkdir(mode=0o700)
    archive = directory / "private.zip"
    old_key = identity.key.read_bytes()
    old_session = policy.finish(identity.database, identity.selected,
        policy.begin(identity.database, identity.selected, "admin", "local")[0], policy.totp(SEED))
    result = recovery.backup(str(identity.config), archive, authorized=True)
    assert recovery.check(archive, result["sha256"])["integrity_valid"]
    import zipfile
    with zipfile.ZipFile(archive) as stream:
        assert {"control/identity.json", "control/auth.key", "control/google.secret", "control/entra.secret"} <= set(stream.namelist())
    root, private = identity.spaces[1][0], identity.config.parent
    root.rename(root.with_name("alpha-retired"))
    root.mkdir(mode=0o700)
    private.rename(private.with_name("alpha-retired"))
    monkeypatch.setattr(workspace, "_ACTIVE", None)
    recovery.restore(archive, result["sha256"], "alpha", root, authorized=True)
    assert identity.key.read_bytes() != old_key
    assert store.session_operator(identity.database, *old_session) is None
    with store.database(identity.database) as db:
        for table in ("operator_factors", "identity_grants", "identity_attempts", "identity_policy_state"):
            assert db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] == 0
    store.update_operator(identity.database, "admin", active=True, password="Renewed-authentication-password-123!", authorized=True)
    with pytest.raises(ValueError, match="Enroll MFA"):
        create_app(identity.options)
    policy.enroll(identity.database, identity.key, "admin", SEED, authorized=True)
    app = create_app(identity.options)
    assert app.config["AUTH_POLICY_ENABLED"]
    assert store.audit_status(identity.database)["events"] > 0


@pytest.mark.parametrize("mutation", ["no-admin-mfa", "no-method", "outside-key", "disabled-secret", "common-tenant", "unknown-user"])
def test_invalid_policy_rejected(identity, mutation):
    data = identity.data
    if mutation == "no-admin-mfa":
        data["mfa_roles"] = ["viewer"]
    elif mutation == "no-method":
        data["local_enabled"] = False
        data["providers"] = {name: {"enabled": False} for name in ("google", "entra")}
    elif mutation == "outside-key":
        data["key_file"] = str(identity.key.parent.parent / "other.key")
    elif mutation == "disabled-secret":
        data["providers"]["google"]["enabled"] = False
    elif mutation == "common-tenant":
        data["providers"]["entra"]["tenant_id"] = "common"
    else:
        data["providers"]["google"]["bindings"][0]["username"] = "unknown"
    identity.path.write_text(json.dumps(data))
    with pytest.raises((ValueError, OSError)):
        create_app(identity.options)


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Opt-in real Chromium unified identity test")
@pytest.mark.parametrize("method", ["local", "google", "entra"])
def test_real_browser_unified_login_mfa_and_logout(identity, method):
    import threading
    from playwright.sync_api import sync_playwright, expect
    from werkzeug.serving import make_server
    server = make_server("127.0.0.1", 0, identity.app, threaded=True)
    base = "http://localhost:" + str(server.server_port)
    identity.data["callback_origin"] = base
    identity.path.write_text(json.dumps(identity.data))
    server.app = create_app(identity.options)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as driver:
            browser = driver.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                seen = []

                def owned_authorization(route):
                    # Browser interception is a synthetic provider UI, not live consent.
                    args = parse_qs(urlsplit(route.request.url).query)
                    identity.trace.args = args
                    seen.append(route.request.url)
                    target = base + "/auth/" + method + "/callback?" + urlencode({"state": args["state"][0], "code": "owned-code"})
                    route.fulfill(status=200, content_type="text/html", body='<a href="' + target.replace("&", "&amp;") + '">Return to owned application</a>')

                def intercept(route):
                    if route.request.url == base + "/auth/" + method + "/start":
                        # Playwright does not route a redirected request separately.
                        # Retain the real start/Set-Cookie, expose its Location as an
                        # owned fixture link, then intercept the new navigation.
                        response = route.fetch(max_redirects=0)
                        assert response.status == 302
                        target = response.headers["location"].replace("&", "&amp;")
                        route.fulfill(status=200, content_type="text/html", body='<a href="' + target + '">Open synthetic provider</a>')
                    elif route.request.url.startswith(base + "/"):
                        route.continue_()
                    elif "/o/oauth2/v2/auth?" in route.request.url or "/oauth2/v2.0/authorize?" in route.request.url:
                        owned_authorization(route)
                    else:
                        route.abort()

                page.route("**/*", intercept)
                page.goto(base + "/login")
                expect(page.get_by_role("button", name="Continue with Google", exact=True)).to_be_visible()
                expect(page.get_by_role("button", name="Continue with Microsoft Entra ID", exact=True)).to_be_visible()
                if method == "local":
                    page.get_by_label("Username", exact=True).fill("admin")
                    page.get_by_label("Password", exact=True).fill(ws.PASSWORD)
                    page.get_by_role("button", name="Sign in", exact=True).click()
                else:
                    page.get_by_role("button", name="Continue with Google" if method == "google" else "Continue with Microsoft Entra ID", exact=True).click()
                    page.get_by_role("link", name="Open synthetic provider").click()
                    page.get_by_role("link", name="Return to owned application").click()
                expect(page.get_by_role("heading", name="Verify your sign-in")).to_be_visible()
                assert page.request.get(base + "/api/scans/1/status").status == 401
                page.get_by_label("Verification code", exact=True).fill(policy.totp(SEED))
                page.get_by_role("button", name="Verify sign-in", exact=True).click()
                page.wait_for_url(base + "/")
                page.goto(base + "/operators")
                assert "admin" in page.content()
                page.get_by_role("button", name="Sign out", exact=True).click()
                expect(page.get_by_role("heading", name="Sign in to HunterQA")).to_be_visible()
                assert len(seen) == (0 if method == "local" else 1)
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
