"""Unified approved-account sign-in; providers prove identity, local policy grants access."""
import base64
import hashlib
import hmac
import http.client
import secrets
import sqlite3
import time
from urllib.parse import urlencode, urlsplit

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, session, url_for

from . import identity_policy as policy, operator_store as store
from .db import get_db
from .oidc_tokens import _engine, _json, _segment, pkce_challenge, verify_id_token
from .operator_oidc import provider_request, signing_keys
from .security import valid_csrf

bp = Blueprint("identity", __name__)
ERRORS = (ValueError, TypeError, KeyError, OSError, UnicodeError, sqlite3.Error, http.client.HTTPException)


def current_policy():
    selected = policy.load(current_app.config["AUTH_CONFIG"])
    if selected["fingerprint"] != current_app.extensions["identity_policy"]["fingerprint"]:
        raise ValueError("Restart after changing the private authentication policy")
    return selected


def audit(action, source):
    try:
        store.audit_event(current_app.config["OPERATOR_DATABASE"], action, source)
    except ERRORS:
        abort(503, "Authentication audit is unavailable.")


def denied(source, reason="identity-login-denied", status=401):
    audit(reason, source)
    return render_template("operator_login.html", error="Sign-in failed. Start again or contact your administrator."), status


def csrf(source):
    if not valid_csrf(request.form.get("csrf_token")):
        audit("identity-invalid-form", source)
        abort(400)


def success(result):
    session.clear()
    session.permanent = True
    session["operator_session"], session["operator_instance"] = result
    return redirect(url_for("main.dashboard"))


def enter(selected, username, source, *, expected_version=None, expires=None):
    database = current_app.config["OPERATOR_DATABASE"]
    grant = policy.begin(database, selected, username, source, expected_version=expected_version, expires=expires)
    if grant is None:
        return denied(source)
    if session.get("operator_session"):
        store.revoke_session(database, session["operator_session"])
    session.clear()
    if grant[1]:
        session["identity_grant"] = grant[0]
        return redirect(url_for("identity.factor"))
    result = policy.finish(database, selected, grant[0])
    return success(result) if result else denied(source)


def local_login():
    try:
        csrf("local")
        selected = current_policy()
        if not selected["data"]["local_enabled"]:
            return denied("local", "identity-method-disabled", 403)
        user, status, _, _ = store.authenticate(current_app.config["OPERATOR_DATABASE"], request.form.get("username", ""),
            request.form.get("password", ""), request.remote_addr or "", verify_only=True)
        if status != "verified":
            return denied("local", status=429 if status == "throttled" else 401)
        return enter(selected, user["username"], "local", expected_version=user["version"])
    except ERRORS:
        return denied("local")


@bp.route("/auth/mfa", methods=["GET", "POST"])
def factor():
    if g.operator:
        return redirect(url_for("main.dashboard"))
    if request.method == "GET":
        if not session.get("identity_grant"):
            return redirect(url_for("operators.login"))
        return render_template("identity_factor.html", error=None)
    try:
        csrf("totp")
        selected = current_policy()
        if request.form.get("cancel") == "yes":
            with store.database(current_app.config["OPERATOR_DATABASE"], write=True) as db:
                db.execute("DELETE FROM identity_grants WHERE token_hash=?", (store._token_hash(session.get("identity_grant")),))
                store._event(db, "identity-challenge-cancelled", "browser")
            session.clear()
            return redirect(url_for("operators.login"))
        result = policy.finish(current_app.config["OPERATOR_DATABASE"], selected, session.get("identity_grant"), request.form.get("code"))
        if result:
            return success(result)
        return render_template("identity_factor.html", error="Verification failed. Use a fresh code or start again."), 401
    except ERRORS:
        return denied("totp")


def provider(selected, name):
    if name not in ("google", "entra") or name not in selected["providers"]:
        return None
    return selected["providers"][name]


@bp.post("/auth/<name>/start")
def provider_start(name):
    source = name if name in {"google", "entra"} else "unknown-provider"
    try:
        csrf(source)
        selected = current_policy()
        config = provider(selected, name)
        if config is None:
            return denied(source, "identity-method-disabled", 404)
        if request.host_url.rstrip("/") != selected["data"]["callback_origin"]:
            return denied(source, "identity-origin-denied", 400)
        state, nonce, verifier, browser = (secrets.token_urlsafe(32) for _ in range(4))
        now = time.time()
        with store.database(current_app.config["OPERATOR_DATABASE"], write=True) as db:
            db.execute("DELETE FROM identity_attempts WHERE expires<=?", (now,))
            db.execute("DELETE FROM login_limits WHERE started<?", (now - 600,))
            key = "identity:" + hashlib.sha256((request.remote_addr or "").encode()).hexdigest()
            limit = db.execute("SELECT count FROM login_limits WHERE key=?", (key,)).fetchone()
            if (limit and limit[0] >= 20) or db.execute("SELECT COUNT(*) FROM identity_attempts").fetchone()[0] >= 256:
                store._event(db, "identity-start-throttled", source)
                return "Sign-in limit reached", 429, {"Retry-After": "600"}
            db.execute("INSERT INTO login_limits VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1", (key, now))
            db.execute("INSERT INTO identity_attempts VALUES(?,?,?,?,?,?,?,?)", (hashlib.sha256(state.encode()).hexdigest(),
                hashlib.sha256(browser.encode()).hexdigest(), name, policy.seal(selected["key"], name + ":nonce", nonce),
                policy.seal(selected["key"], name + ":verifier", verifier), now, now + 300, selected["fingerprint"]))
            store._event(db, "identity-provider-started", source)
        session["identity_browser"] = browser
        return redirect(config["authorization_endpoint"] + "?" + urlencode({"response_type": "code", "client_id": config["client_id"],
            "redirect_uri": config["redirect_uri"], "scope": "openid", "state": state, "nonce": nonce,
            "code_challenge": pkce_challenge(verifier), "code_challenge_method": "S256"}))
    except ERRORS:
        return denied(source)


@bp.get("/auth/<name>/callback")
def provider_callback(name):
    source = name if name in {"google", "entra"} else "unknown-provider"
    try:
        selected = current_policy()
        config = provider(selected, name)
        if config is None:
            return denied(source, "identity-method-disabled", 404)
        allowed = {"code", "state", "iss", "session_state", "scope", "authuser", "prompt", "error", "error_description", "error_uri"}
        if (request.base_url != config["redirect_uri"] or set(request.args) - allowed
                or any(len(request.args.getlist(k)) != 1 for k in request.args)
                or any(len(v) > 2048 or any(ord(c) < 32 for c in v) for v in request.args.values())
                or ("iss" in request.args and request.args["iss"] not in config["issuers"])):
            raise ValueError("Invalid provider callback")
        state, browser = request.args.get("state", ""), session.get("identity_browser", "")
        if not all(isinstance(v, str) and len(v) == 43 and v.isascii() for v in (state, browser)):
            raise ValueError("Missing browser-bound state")
        now = time.time()
        with store.database(current_app.config["OPERATOR_DATABASE"], write=True) as db:
            state_hash = hashlib.sha256(state.encode()).hexdigest()
            attempt = db.execute("SELECT * FROM identity_attempts WHERE state_hash=?", (state_hash,)).fetchone()
            if (not attempt or attempt["provider"] != name or attempt["fingerprint"] != selected["fingerprint"]
                    or not attempt["created"] <= now < attempt["expires"] or attempt["expires"] - attempt["created"] != 300
                    or not hmac.compare_digest(attempt["browser_hash"], hashlib.sha256(browser.encode()).hexdigest())):
                raise ValueError("State rejected")
            db.execute("DELETE FROM identity_attempts WHERE state_hash=?", (state_hash,))
        session.pop("identity_browser", None)
        code = request.args.get("code", "")
        if "error" in request.args or not code or not all(33 <= ord(c) < 127 for c in code):
            raise ValueError("Authorization grant rejected")
        nonce = policy.unseal(selected["key"], name + ":nonce", attempt["nonce_cipher"])
        verifier = policy.unseal(selected["key"], name + ":verifier", attempt["verifier_cipher"])
        transport = current_app.config.get("IDENTITY_TRANSPORT") or provider_request
        response = transport(config, "token", urlencode({"grant_type": "authorization_code", "code": code,
            "client_id": config["client_id"], "client_secret": config["secret"], "redirect_uri": config["redirect_uri"], "code_verifier": verifier}).encode("ascii"))
        if not isinstance(response, dict) or not isinstance(response.get("id_token"), str) or len(response["id_token"]) > 16384:
            raise ValueError("Invalid token response")
        token = response["id_token"]
        if len(token.split(".")) != 3:
            raise ValueError("Malformed signed identity")
        claims = _json(_segment(token.split(".")[1]))
        if not isinstance(claims, dict):
            raise ValueError("Invalid signed claims")
        issuer = claims.get("iss")
        if issuer not in config["issuers"]:
            raise ValueError("Issuer rejected")
        token_policy = {"schema_version": 1, "issuer": config["issuer"], "client_id": config["client_id"], "expected_nonce": nonce,
            "max_lifetime_seconds": 86400, "max_age_seconds": 300, "expected_subject": None,
            "expected_tenant": None, "allow_loopback_issuer": False}
        keys = signing_keys(transport(config, "jwks"))
        if not verify_id_token(token, keys, token_policy, google_issuer_alias=name == "google" and issuer == "accounts.google.com")["accepted"]:
            raise ValueError("Signed identity rejected")
        if config["tenant"] is not None and claims.get("tid") != config["tenant"]:
            raise ValueError("Entra tenant differs")
        if "at_hash" in claims:
            access = response.get("access_token")
            if not isinstance(access, str) or not 1 <= len(access) <= 16384 or not all(33 <= ord(c) < 127 for c in access):
                raise ValueError("Invalid access-token binding")
            digest = base64.urlsafe_b64encode(hashlib.sha256(access.encode()).digest()[:16]).decode().rstrip("=")
            if not isinstance(claims["at_hash"], str) or not hmac.compare_digest(claims["at_hash"].encode(), digest.encode()):
                raise ValueError("Access-token binding rejected")
        username = next((row["username"] for row in config["bindings"] if row["subject"] == claims.get("sub")), None)
        if username is None:
            reference = policy.candidate(current_app.config["OPERATOR_DATABASE"], selected, name, claims["sub"], claims["exp"])
            if reference is None:
                return denied(source)
            return render_template("operator_login.html", error="Identity verified, but access is not approved. "
                "Give this five-minute reference only to your local OS administrator: " + reference), 401
        return enter(selected, username, name, expires=claims["exp"])
    except ERRORS:
        return denied(source)


def init_identity(app):
    with app.app_context():
        db = get_db()
        marker = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='dashboard_identity_policy'").fetchone()
        required = marker and db.execute("SELECT 1 FROM dashboard_identity_policy WHERE id=1").fetchone()
    if not app.config.get("AUTH_CONFIG"):
        if required:
            raise ValueError("Restore this dashboard's required unified authentication policy")
        app.config["AUTH_POLICY_ENABLED"] = False
        return
    if not app.config.get("OPERATOR_DATABASE") or app.config.get("OIDC_CONFIG"):
        raise ValueError("Unified policy requires one private operator store and replaces legacy OIDC configuration")
    if app.config.get("IDENTITY_TRANSPORT") is not None and not app.testing:
        raise ValueError("Custom identity transports are restricted to owned tests")
    selected = policy.load(app.config["AUTH_CONFIG"])
    if app.config.get("WORKSPACE_PUBLIC_ORIGIN"):
        if selected["data"]["callback_origin"] != app.config["WORKSPACE_PUBLIC_ORIGIN"]:
            raise ValueError("Unified callback origin must match the authenticated HTTPS edge")
    elif urlsplit(selected["data"]["callback_origin"]).scheme != "http":
        raise ValueError("Local unified mode requires an explicit HTTP loopback origin")
    if selected["providers"]:
        _engine()
    database = app.config["OPERATOR_DATABASE"]
    with store.database(database, write=True) as db:
        policy.schema(db)
        users = {row["username"]: row for row in db.execute("SELECT * FROM operators")}
        instance = db.execute("SELECT instance FROM identity").fetchone()[0]
        for config in selected["providers"].values():
            if any(row["username"] not in users for row in config["bindings"]):
                raise ValueError("Provider bindings require existing approved operators")
        for user in users.values():
            if user["active"] and user["role"] in selected["data"]["mfa_roles"]:
                factor = db.execute("SELECT * FROM operator_factors WHERE user_id=?", (user["id"],)).fetchone()
                if factor is None:
                    raise ValueError("Enroll MFA for every active account required by policy before serving")
                policy.seed_bytes(policy.unseal(selected["key"], "totp:" + instance + ":" + str(user["id"]), factor["secret_cipher"]))
        prior = db.execute("SELECT fingerprint FROM identity_policy_state WHERE id=1").fetchone()
        if not prior or prior[0] != selected["fingerprint"]:
            db.execute("DELETE FROM operator_sessions")
            db.execute("DELETE FROM identity_grants")
            db.execute("DELETE FROM identity_attempts")
            db.execute("DELETE FROM identity_candidates")
            if db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='operator_oidc_attempts'").fetchone():
                db.execute("DELETE FROM operator_oidc_attempts")
            db.execute("INSERT INTO identity_policy_state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint", (selected["fingerprint"],))
            store._event(db, "identity-policy-activated-sessions-revoked", "private-policy")
    with app.app_context():
        with get_db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS dashboard_identity_policy(id INTEGER PRIMARY KEY CHECK(id=1))")
            db.execute("INSERT OR IGNORE INTO dashboard_identity_policy VALUES(1)")
    app.extensions["identity_policy"] = selected
    app.config.update(AUTH_POLICY_ENABLED=True, AUTH_LOCAL_ENABLED=selected["data"]["local_enabled"],
        AUTH_PROVIDERS=list(selected["providers"]), OIDC_ENABLED=False,
        OIDC_FORM_ACTION=" ".join(config["authorization_endpoint"] for config in selected["providers"].values()),
        SESSION_COOKIE_SAMESITE="Lax" if selected["providers"] else "Strict")
    app.register_blueprint(bp)

    @app.before_request
    def require_unchanged_identity_policy():
        try:
            current_policy()
        except ERRORS:
            abort(503, "Authentication configuration changed; restart under OS administration.")
