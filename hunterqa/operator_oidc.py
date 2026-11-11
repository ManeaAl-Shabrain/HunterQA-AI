"""Explicit OIDC code/PKCE sign-in to existing local operator accounts."""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import secrets
import socket
import sqlite3
import ssl
import time
from urllib.parse import urlencode, urlsplit

from flask import Blueprint, abort, current_app, redirect, render_template, request, session, url_for

from . import cloud_transport, operator_store as store
from .bounty import BountyPolicy, _decode_json, resolve_pinned
from .cloud_inventory_common import bounded_json
from .db import get_db
from .oidc_tokens import _engine, _json, _segment, pkce_challenge, verify_id_token
from .security import valid_csrf
from .source_files import read_bounded

bp = Blueprint("operator_oidc", __name__)
FIELDS = {"schema_version", "issuer", "client_id", "authorization_endpoint", "token_endpoint", "jwks_uri",
    "redirect_uri", "client_secret_file", "bindings", "local_password_login", "allow_private_provider"}


def _text(value, maximum=256):
    return isinstance(value, str) and 1 <= len(value) <= maximum and all(33 <= ord(c) < 127 for c in value)


def _endpoint(value):
    if not _text(value, 2048):
        raise ValueError("Invalid explicit OIDC HTTPS endpoint")
    parts = urlsplit(value)
    if (parts.scheme != "https" or not parts.hostname or (parts.port is not None and not 1 <= parts.port <= 65535)
            or parts.username is not None or parts.password is not None or parts.query or parts.fragment
            or any(c in value for c in ("%", "\\", ";", "'", '"')) or "//" in parts.path or any(s in (".", "..") for s in parts.path.split("/"))):
        raise ValueError("Invalid explicit OIDC HTTPS endpoint")
    return parts


def load_config(path):
    raw = read_bounded(store._path(path), 65536)
    data = _decode_json(raw)
    if (not isinstance(data, dict) or set(data) != FIELDS or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or not _text(data["client_id"]) or type(data["local_password_login"]) is not bool
            or type(data["allow_private_provider"]) is not bool):
        raise ValueError("Invalid private OIDC configuration")
    for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        _endpoint(data[key])
    callback = urlsplit(data["redirect_uri"])
    if (not _text(data["redirect_uri"], 2048) or callback.scheme not in ("http", "https")
            or not callback.hostname or (callback.scheme == "http" and (callback.hostname not in ("127.0.0.1", "localhost", "::1") or callback.port is None))
            or (callback.port is not None and not 1 <= callback.port <= 65535)
            or callback.path != "/oidc/callback" or callback.query or callback.fragment
            or callback.username is not None or callback.password is not None):
        raise ValueError("OIDC requires an exact registered loopback callback")
    values = data["bindings"]
    if not isinstance(values, list) or not 1 <= len(values) <= 256:
        raise ValueError("Define explicit issuer-subject to local operator bindings")
    subjects = set()
    for row in values:
        if (not isinstance(row, dict) or set(row) != {"subject", "username"} or not _text(row["subject"])
                or not isinstance(row["username"], str) or not store.NAME.fullmatch(row["username"]) or row["subject"] in subjects):
            raise ValueError("Invalid or duplicate OIDC subject binding")
        subjects.add(row["subject"])
    secret = ""  # nosec B105: absence of a client secret for an explicit public PKCE client
    if data["client_secret_file"] is not None:
        selected = store._path(data["client_secret_file"])
        if selected.parent != store._path(path).parent:
            raise ValueError("OIDC client secret must stay beside its private configuration")
        secret = read_bounded(selected, 4096).decode("ascii").rstrip("\r\n")
        if not _text(secret, 2048) or len(secret) < 16:
            raise ValueError("Invalid private OIDC client secret")
    return data, secret, hashlib.sha256(raw + b"\x00" + secret.encode()).hexdigest()


def _dial(ip, port, end):
    channel = socket.socket(socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    try:
        channel.settimeout(cloud_transport.remaining(end))
        channel.connect((ip, port))
        return channel
    except BaseException:
        channel.close()
        raise


class _Connection(http.client.HTTPSConnection):
    def __init__(self, host, ip, port=443):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
        context.load_default_certs()
        super().__init__(host, port, timeout=5, context=context)
        self.ip, self.debuglevel = ip, 0

    def connect(self):
        end = cloud_transport.deadline()
        channel = _dial(self.ip, self.port, end)
        self.sock = cloud_transport.finish_tls(channel, self._context, self.host, end)


def provider_request(config, action, body=None):
    if action not in ("token", "jwks"):
        raise ValueError("Unsupported OIDC request")
    parts = _endpoint(config["token_endpoint" if action == "token" else "jwks_uri"])
    host, path, port = parts.hostname, parts.path or "/", parts.port or 443
    policy = BountyPolicy.from_dict({"program": "Explicit operator OIDC provider", "platform": "private",
        "authorization_reference": "Private OS-admin provider configuration", "acknowledged_authorization": True,
        "allowed_hosts": [host], "allowed_ports": [port], "allowed_paths": [path], "methods": ["GET"],
        "lab_mode": config["allow_private_provider"], "allow_private_network": config["allow_private_provider"],
        "max_requests": 1, "interval_seconds": 0.5})
    ip = resolve_pinned(policy, host, port)
    connection = _Connection(host, ip, port)
    try:
        connection.connect()
        headers = {"Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close"}
        if action == "token":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        connection.request("POST" if action == "token" else "GET", path, body=body, headers=headers)
        response = cloud_transport.read_response(connection.getresponse(), 65536 if action == "token" else 262144)
        if response["status"] != 200:
            raise ValueError("OIDC provider response rejected")
        return bounded_json(response["body"])
    finally:
        connection.close()


def _current():
    config, secret, fingerprint = load_config(current_app.config["OIDC_CONFIG"])
    if fingerprint != current_app.extensions["oidc_fingerprint"]:
        raise ValueError("Restart after changing private OIDC configuration")
    return config, secret, fingerprint


def _failure():
    return render_template("operator_login.html", error="Single sign-on failed. Start again or contact your administrator."), 401


def signing_keys(data):
    if not isinstance(data, dict) or set(data) != {"keys"} or not isinstance(data["keys"], list) or not 1 <= len(data["keys"]) <= 32:
        raise ValueError("Invalid provider signing-key set")
    selected = []
    for row in data["keys"]:
        if not isinstance(row, dict):
            raise ValueError("Invalid provider signing key")
        if row.get("kty") == "RSA" and row.get("alg", "RS256") == "RS256" and row.get("use", "sig") == "sig":
            # Certificates/thumbprints/provider metadata are not trust anchors
            # here. Only bounded RSA verification material reaches the verifier.
            selected.append({k: row[k] for k in ("kty", "kid", "n", "e", "alg", "use", "key_ops") if k in row})
    return {"keys": selected}


@bp.post("/oidc/start")
def start():
    if not valid_csrf(request.form.get("csrf_token")):
        abort(400)
    try:
        config, _, fingerprint = _current()
        callback = urlsplit(config["redirect_uri"])
        if request.host_url.rstrip("/") != callback.scheme + "://" + callback.netloc:
            abort(400, "Open this workspace at its registered sign-in address.")
        state, nonce, verifier, browser = (secrets.token_urlsafe(32) for _ in range(4))
        now = time.time()
        with store.database(current_app.config["OPERATOR_DATABASE"], write=True) as db:
            db.execute("DELETE FROM operator_oidc_attempts WHERE expires<=?", (now,))
            db.execute("DELETE FROM login_limits WHERE started<?", (now - 600,))
            key = "oidc:" + hashlib.sha256((request.remote_addr or "").encode()).hexdigest()
            limit = db.execute("SELECT count FROM login_limits WHERE key=?", (key,)).fetchone()
            if (limit and limit[0] >= 20) or db.execute("SELECT COUNT(*) FROM operator_oidc_attempts").fetchone()[0] >= 256:
                return "Sign-in rate limit reached", 429, {"Retry-After": "600"}
            db.execute("INSERT INTO login_limits VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1", (key, now))
            db.execute("INSERT INTO operator_oidc_attempts VALUES(?,?,?,?,?,?,?)",
                (hashlib.sha256(state.encode()).hexdigest(), hashlib.sha256(browser.encode()).hexdigest(), nonce, verifier, now, now + 300, fingerprint))
        session["oidc_browser"] = browser
        location = config["authorization_endpoint"] + "?" + urlencode({"response_type": "code", "client_id": config["client_id"],
            "redirect_uri": config["redirect_uri"], "scope": "openid", "state": state, "nonce": nonce,
            "code_challenge": pkce_challenge(verifier), "code_challenge_method": "S256"})
        return redirect(location)
    except (ValueError, TypeError, OSError, sqlite3.Error, UnicodeError):
        return _failure()


@bp.get("/oidc/callback")
def callback():
    try:
        config, secret, fingerprint = _current()
        expected = urlsplit(config["redirect_uri"])
        if request.base_url != config["redirect_uri"] or request.host != expected.netloc:
            raise ValueError
        allowed = {"state", "code", "iss", "session_state", "scope", "authuser", "prompt", "error", "error_description", "error_uri"}
        if (set(request.args) - allowed or any(len(request.args.getlist(k)) != 1 for k in request.args)
                or any(not isinstance(v, str) or len(v) > 2048 or any(ord(c) < 32 for c in v) for v in request.args.values())):
            raise ValueError
        state, browser = request.args.get("state"), session.get("oidc_browser")
        if (not _text(state, 128) or not _text(browser, 128) or ("iss" in request.args and request.args["iss"] != config["issuer"])):
            raise ValueError
        now = time.time()
        with store.database(current_app.config["OPERATOR_DATABASE"], write=True) as db:
            key = hashlib.sha256(state.encode()).hexdigest()
            attempt = db.execute("SELECT * FROM operator_oidc_attempts WHERE state_hash=?", (key,)).fetchone()
            if (attempt is None or not hmac.compare_digest(attempt["browser_hash"], hashlib.sha256(browser.encode()).hexdigest())
                    or not attempt["created"] <= now < attempt["expires"] or attempt["expires"] - attempt["created"] != 300
                    or attempt["config_hash"] != fingerprint):
                raise ValueError
            db.execute("DELETE FROM operator_oidc_attempts WHERE state_hash=?", (key,))
        session.pop("oidc_browser", None)
        if "error" in request.args or not _text(request.args.get("code"), 2048):
            raise ValueError
        params = {"grant_type": "authorization_code", "code": request.args["code"], "client_id": config["client_id"],
            "redirect_uri": config["redirect_uri"], "code_verifier": attempt["verifier"]}
        if secret:
            params["client_secret"] = secret
        transport = current_app.config.get("OIDC_TRANSPORT") or provider_request
        token_response = transport(config, "token", urlencode(params).encode("ascii"))
        if not isinstance(token_response, dict) or not _text(token_response.get("id_token"), 16384):
            raise ValueError
        jwks = signing_keys(transport(config, "jwks"))
        policy = {"schema_version": 1, "issuer": config["issuer"], "client_id": config["client_id"],
            "expected_nonce": attempt["nonce"], "max_lifetime_seconds": 86400, "max_age_seconds": 300,
            "expected_subject": None, "expected_tenant": None, "allow_loopback_issuer": False}
        token = token_response["id_token"]
        verified = verify_id_token(token, jwks, policy)
        if not verified["accepted"]:
            raise ValueError
        claims = _json(_segment(token.split(".")[1]))
        if "at_hash" in claims:
            access = token_response.get("access_token")
            if not _text(access, 16384):
                raise ValueError
            binding = base64.urlsafe_b64encode(hashlib.sha256(access.encode("ascii")).digest()[:16]).decode().rstrip("=")
            if not isinstance(claims["at_hash"], str) or not hmac.compare_digest(claims["at_hash"].encode(), binding.encode()):
                raise ValueError
        username = next((row["username"] for row in config["bindings"] if row["subject"] == claims["sub"]), None)
        if username is None:
            raise ValueError
        user, status, instance, token = store.federated_session(current_app.config["OPERATOR_DATABASE"], username,
            max_seconds=min(store.SESSION_SECONDS, claims["exp"] - int(time.time())))
        if status != "ok":
            raise ValueError
        session.clear()
        session.permanent = True
        session["operator_session"], session["operator_instance"] = token, instance
        return redirect(url_for("main.dashboard"))
    except (ValueError, TypeError, OSError, sqlite3.Error, UnicodeError, KeyError, http.client.HTTPException):
        return _failure()


def init_oidc(app):
    with app.app_context():
        with get_db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS dashboard_federation(id INTEGER PRIMARY KEY CHECK(id=1), required INTEGER NOT NULL)")
            row = db.execute("SELECT required FROM dashboard_federation WHERE id=1").fetchone()
            required = bool(row and row[0])
    if not app.config.get("OIDC_CONFIG"):
        if required:
            raise ValueError("Restore this dashboard's required OIDC configuration")
        app.config["OIDC_ENABLED"] = False
        return
    if not app.config.get("OPERATOR_DATABASE"):
        raise ValueError("OIDC requires the private local operator database")
    if app.config.get("OIDC_TRANSPORT") is not None and not app.testing:
        raise ValueError("Custom OIDC transports are restricted to owned tests")
    _engine()
    config, _, fingerprint = load_config(app.config["OIDC_CONFIG"])
    callback_uri = urlsplit(config["redirect_uri"])
    if app.config.get("WORKSPACE_PUBLIC_ORIGIN"):
        if (callback_uri.scheme + "://" + callback_uri.netloc != app.config["WORKSPACE_PUBLIC_ORIGIN"]
                or config["local_password_login"] or config["client_secret_file"] is None):
            raise ValueError("Hosted workspace requires its exact HTTPS OIDC callback, confidential client and SSO-only login")
    elif callback_uri.hostname not in ("127.0.0.1", "localhost", "::1") or callback_uri.port is None:
        raise ValueError("Local operator mode requires an exact loopback callback")
    known = {u["username"] for u in store.status(app.config["OPERATOR_DATABASE"])["operators"]}
    if any(row["username"] not in known for row in config["bindings"]):
        raise ValueError("OIDC bindings must reference existing local operators")
    with store.database(app.config["OPERATOR_DATABASE"], write=True) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS operator_oidc_attempts(
            state_hash TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, nonce TEXT NOT NULL, verifier TEXT NOT NULL,
            created REAL NOT NULL, expires REAL NOT NULL, config_hash TEXT NOT NULL)""")
    with app.app_context():
        with get_db() as db:
            db.execute("INSERT OR REPLACE INTO dashboard_federation VALUES(1,1)")
    app.extensions["oidc_fingerprint"] = fingerprint
    app.config.update(OIDC_ENABLED=True, OIDC_LOCAL_PASSWORD=config["local_password_login"], SESSION_COOKIE_SAMESITE="Lax",
        OIDC_FORM_ACTION=config["authorization_endpoint"])
    app.register_blueprint(bp)
