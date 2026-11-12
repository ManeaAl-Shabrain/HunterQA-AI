"""Explicit local/Google/Entra policy and encrypted RFC 6238 operator factors."""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import time
from urllib.parse import urlsplit
import uuid

from . import operator_store as store
from .bounty import _decode_json
from .source_files import read_bounded
from .trusted_edge import public_origin

POLICY_FIELDS = {"schema_version", "local_enabled", "mfa_roles", "key_file", "callback_origin", "providers"}


def _cipher(key):
    from cryptography.fernet import Fernet
    return Fernet(base64.urlsafe_b64encode(bytes.fromhex(key)))


def seal(key, purpose, value):
    return _cipher(key).encrypt(json.dumps({"purpose": purpose, "value": value}, sort_keys=True).encode()).decode("ascii")


def unseal(key, purpose, value):
    from cryptography.fernet import InvalidToken
    try:
        payload = _decode_json(_cipher(key).decrypt(value.encode("ascii")))
        if set(payload) != {"purpose", "value"} or payload["purpose"] != purpose:
            raise ValueError("Encrypted authentication context differs")
        return payload["value"]
    except (InvalidToken, UnicodeError, TypeError, KeyError) as error:
        raise ValueError("Encrypted authentication state rejected") from error


def seed_bytes(secret):
    if not isinstance(secret, str) or not re.fullmatch(r"[A-Z2-7]{32}", secret):
        raise ValueError("Use a 160-bit Base32 authenticator secret")
    return base64.b32decode(secret)


def totp(secret, when=None, *, digits=6):
    counter = int(time.time() if when is None else when) // 30
    raw = hmac.digest(seed_bytes(secret), struct.pack(">Q", counter), "sha1")
    offset = raw[-1] & 15
    value = struct.unpack(">I", raw[offset:offset + 4])[0] & 0x7fffffff
    return str(value % 10 ** digits).zfill(digits)


def matched_step(secret, code, now, last_step=-1):
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
        return None
    step = int(now) // 30
    matches = [candidate for candidate in (step - 1, step, step + 1) if candidate >= 0 and candidate > last_step
        and hmac.compare_digest(totp(secret, candidate * 30), code)]
    return max(matches) if matches else None


def schema(db):
    db.execute("CREATE TABLE IF NOT EXISTS operator_factors(user_id INTEGER PRIMARY KEY, secret_cipher TEXT NOT NULL, last_step INTEGER NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS identity_policy_state(id INTEGER PRIMARY KEY CHECK(id=1), fingerprint TEXT NOT NULL)")
    db.execute("""CREATE TABLE IF NOT EXISTS identity_grants(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,
        version INTEGER NOT NULL,instance TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,
        session_expires REAL NOT NULL,attempts INTEGER NOT NULL,source TEXT NOT NULL,fingerprint TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS identity_attempts(state_hash TEXT PRIMARY KEY,browser_hash TEXT NOT NULL,
        provider TEXT NOT NULL,nonce_cipher TEXT NOT NULL,verifier_cipher TEXT NOT NULL,created REAL NOT NULL,
        expires REAL NOT NULL,fingerprint TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS identity_candidates(reference_hash TEXT PRIMARY KEY,provider TEXT NOT NULL,
        subject_cipher TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,fingerprint TEXT NOT NULL)""")


def enroll(database, key_file, username, secret, *, authorized=False, confirmed_step=-1):
    if authorized is not True:
        raise PermissionError("MFA enrollment requires --authorized")
    store._name(username)
    seed_bytes(secret)
    database, key_file = store._path(database), store._path(key_file)
    if database.parent != key_file.parent or database == key_file:
        raise ValueError("MFA key must belong to the same private identity directory")
    key = store.read_session_key(key_file)
    with store.database(database, write=True) as db:
        schema(db)
        user = db.execute("SELECT * FROM operators WHERE username=?", (username,)).fetchone()
        if user is None:
            raise ValueError("Only an existing approved operator can enroll")
        instance = db.execute("SELECT instance FROM identity").fetchone()[0]
        blob = seal(key, "totp:" + instance + ":" + str(user["id"]), secret)
        db.execute("INSERT INTO operator_factors VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET secret_cipher=excluded.secret_cipher,last_step=excluded.last_step", (user["id"], blob, confirmed_step))
        db.execute("UPDATE operators SET version=version+1 WHERE id=?", (user["id"],))
        db.execute("DELETE FROM operator_sessions WHERE user_id=?", (user["id"],))
        db.execute("DELETE FROM identity_grants WHERE user_id=?", (user["id"],))
        store._event(db, "os-admin-mfa-enrolled-sessions-revoked", username)
    return {"username": username, "mfa_enrolled": True, "secret_stored_encrypted": True, "secret_displayed": False}


def _origin(value):
    if not isinstance(value, str) or not value.isascii() or len(value) > 2048:
        raise ValueError("Invalid authentication callback origin")
    parts = urlsplit(value)
    if parts.scheme == "https":
        if public_origin(value) != value:
            raise ValueError("Use a canonical HTTPS callback origin")
    elif (parts.scheme != "http" or parts.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parts.port is None or not 1024 <= parts.port <= 65535 or parts.path or parts.query or parts.fragment
            or parts.username is not None or parts.password is not None):
        raise ValueError("Use an explicit registered loopback origin or HTTPS origin")
    elif value != "http://" + ("[::1]" if parts.hostname == "::1" else parts.hostname) + ":" + str(parts.port):
        raise ValueError("Use a canonical loopback origin")
    return value


def load(path):
    path = store._path(path)
    raw = read_bounded(path, 65536)
    data = _decode_json(raw)
    if (not isinstance(data, dict) or set(data) != POLICY_FIELDS or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or type(data["local_enabled"]) is not bool or not isinstance(data["mfa_roles"], list)
            or not 1 <= len(data["mfa_roles"]) <= 3 or any(type(v) is not str for v in data["mfa_roles"])
            or len(set(data["mfa_roles"])) != len(data["mfa_roles"]) or "admin" not in data["mfa_roles"]
            or set(data["mfa_roles"]) - set(store.ROLES) or not isinstance(data["providers"], dict)
            or set(data["providers"]) != {"google", "entra"}):
        raise ValueError("Invalid identity policy; administrator MFA is mandatory")
    origin = _origin(data["callback_origin"])
    key_file = store._path(data["key_file"])
    reserved = {path, path.parent / "workspace.json", path.parent / "operators.sqlite3", path.parent / "session.key", path.parent / "edge.key"}
    if key_file.parent != path.parent or key_file in reserved:
        raise ValueError("Use a separate MFA encryption key beside the policy")
    key, providers, secret_hashes = store.read_session_key(key_file), {}, []
    reserved.add(key_file)
    for name, value in data["providers"].items():
        if not isinstance(value, dict) or type(value.get("enabled")) is not bool:
            raise ValueError("Invalid provider switch")
        if value["enabled"] is False:
            if set(value) != {"enabled"}:
                raise ValueError("Disabled provider entries contain only enabled=false")
            continue
        fields = {"enabled", "client_id", "client_secret_file", "bindings"} | ({"tenant_id"} if name == "entra" else set())
        if set(value) != fields or not isinstance(value["client_id"], str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,256}", value["client_id"]):
            raise ValueError("Invalid provider client configuration")
        bindings = value["bindings"]
        if not isinstance(bindings, list) or not 0 <= len(bindings) <= 256:
            raise ValueError("Use explicit approved subject bindings")
        subjects = set()
        for row in bindings:
            if (not isinstance(row, dict) or set(row) != {"subject", "username"} or not isinstance(row["subject"], str)
                    or not re.fullmatch(r"[!-~]{1,256}", row["subject"]) or row["subject"] in subjects):
                raise ValueError("Invalid or duplicate subject binding")
            store._name(row["username"])
            subjects.add(row["subject"])
        secret_file = store._path(value["client_secret_file"])
        if secret_file.parent != path.parent or secret_file in reserved:
            raise ValueError("Use a distinct private client secret for each provider")
        reserved.add(secret_file)
        secret = read_bounded(secret_file, 4096).decode("ascii").rstrip("\r\n")
        if not re.fullmatch(r"[!-~]{16,2048}", secret):
            raise ValueError("Invalid private client secret")
        secret_hashes.append(hashlib.sha256(secret.encode()).hexdigest())
        if name == "google":
            issuer = "https://accounts.google.com"
            auth, token, jwks = issuer + "/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "https://www.googleapis.com/oauth2/v3/certs"
            issuers = [issuer, "accounts.google.com"]
        else:
            tenant = value["tenant_id"]
            if not isinstance(tenant, str) or str(uuid.UUID(tenant)) != tenant:
                raise ValueError("Entra requires one canonical tenant UUID")
            base = "https://login.microsoftonline.com/" + tenant
            issuer, auth, token, jwks = base + "/v2.0", base + "/oauth2/v2.0/authorize", base + "/oauth2/v2.0/token", base + "/discovery/v2.0/keys"
            issuers = [issuer]
        providers[name] = {"issuer": issuer, "issuers": issuers, "authorization_endpoint": auth, "token_endpoint": token,
            "jwks_uri": jwks, "redirect_uri": origin + "/auth/" + name + "/callback", "allow_private_provider": False,
            "client_id": value["client_id"], "secret": secret, "bindings": bindings, "tenant": value.get("tenant_id")}
    if not data["local_enabled"] and not providers:
        raise ValueError("Enable at least one authentication method")
    fingerprint = hashlib.sha256(raw + key.encode() + json.dumps(secret_hashes).encode()).hexdigest()
    return {"data": data, "providers": providers, "key": key, "fingerprint": fingerprint}


def candidate(database, selected, name, subject, expires):
    """Retain a verified unbound subject for OS-admin review; never grant access."""
    if name not in selected["providers"] or not isinstance(subject, str) or not re.fullmatch(r"[!-~]{1,256}", subject):
        raise ValueError("Unsupported verified subject")
    now, reference = time.time(), secrets.token_urlsafe(32)
    hashed = store._token_hash(reference)
    with store.database(database, write=True) as db:
        db.execute("DELETE FROM identity_candidates WHERE expires<=?", (now,))
        if db.execute("SELECT COUNT(*) FROM identity_candidates").fetchone()[0] >= 32:
            store._event(db, "identity-subject-review-capacity", name)
            return None
        db.execute("INSERT INTO identity_candidates VALUES(?,?,?,?,?,?)", (hashed, name,
            seal(selected["key"], "subject:" + selected["fingerprint"] + ":" + hashed, subject), now,
            min(now + 300, expires), selected["fingerprint"]))
        store._event(db, "identity-subject-verified-awaiting-os-approval", name)
    return reference


def approve(workspace_config, name, username, reference, *, authorized=False):
    if authorized is not True:
        raise PermissionError("Identity approval requires --authorized")
    from . import workspace
    store._name(username)
    hashed = store._token_hash(reference)
    if hashed is None or name not in {"google", "entra"}:
        raise ValueError("Invalid subject approval reference")
    settings = workspace.load(workspace_config)
    path = store._path(settings.get("AUTH_CONFIG") or "")
    with store.database(settings["OPERATOR_DATABASE"], write=True) as db:
        selected = load(path)
        schema(db)
        row = db.execute("SELECT * FROM identity_candidates WHERE reference_hash=?", (hashed,)).fetchone()
        now = time.time()
        if (not row or row["provider"] != name or name not in selected["providers"]
                or row["fingerprint"] != selected["fingerprint"] or not row["created"] <= now < row["expires"]):
            raise ValueError("Subject approval is expired, changed or unavailable; repeat provider verification")
        user = db.execute("SELECT * FROM operators WHERE username=?", (username,)).fetchone()
        if not user or not user["active"]:
            raise ValueError("Approve only an existing active local account")
        if user["role"] in selected["data"]["mfa_roles"] and not db.execute("SELECT 1 FROM operator_factors WHERE user_id=?", (user["id"],)).fetchone():
            raise ValueError("Enroll this approved account's MFA before binding an identity")
        subject = unseal(selected["key"], "subject:" + selected["fingerprint"] + ":" + hashed, row["subject_cipher"])
        if not isinstance(subject, str) or not re.fullmatch(r"[!-~]{1,256}", subject):
            raise ValueError("Invalid verified subject")
        data = selected["data"]
        bindings = data["providers"][name]["bindings"]
        if len(bindings) >= 256 or any(binding["subject"] == subject for binding in bindings):
            raise ValueError("Subject is already bound or the binding limit is reached")
        bindings.append({"subject": subject, "username": username})
        # Audit failure must happen before publishing a new identity binding.
        store._event(db, "os-admin-approved-provider-subject", username, provider=name)
        temporary = path.parent / ("identity-approval-" + secrets.token_hex(12) + ".tmp")
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(data, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        db.execute("DELETE FROM identity_candidates")
        db.execute("DELETE FROM operator_sessions")
        db.execute("DELETE FROM identity_grants")
        db.execute("DELETE FROM identity_attempts")
    return {"provider": name, "username": username, "subject": subject, "approved": True,
        "restart_required": True, "account_created": False, "role_changed": False}


def approve_cli(workspace_config, name, username, *, reference_stdin=False, authorized=False):
    import getpass
    import sys
    if authorized is not True:
        raise PermissionError("Identity approval requires --authorized")
    if reference_stdin:
        reference = sys.stdin.read(129).strip()
    else:
        if not sys.stdin.isatty():
            raise ValueError("Use a private terminal or explicitly select --reference-stdin")
        reference = getpass.getpass("Verified browser enrollment reference: ")
    return approve(workspace_config, name, username, reference, authorized=True)


def begin(database, policy, username, source, *, expected_version=None, expires=None):
    now = time.time()
    with store.database(database, write=True) as db:
        schema(db)
        user = db.execute("SELECT * FROM operators WHERE username=?", (username,)).fetchone()
        if not user or not user["active"] or (expected_version is not None and user["version"] != expected_version):
            store._event(db, "identity-denied", "unavailable-account", source=source)
            return None
        factor = db.execute("SELECT user_id FROM operator_factors WHERE user_id=?", (user["id"],)).fetchone()
        if user["role"] in policy["data"]["mfa_roles"] and factor is None:
            store._event(db, "identity-denied-mfa-not-enrolled", username, source=source)
            return None
        db.execute("DELETE FROM identity_grants WHERE expires<=?", (now,))
        db.execute("DELETE FROM login_limits WHERE started<?", (now - 600,))
        key = "grant:" + str(user["id"])
        count = db.execute("SELECT count FROM login_limits WHERE key=?", (key,)).fetchone()
        if (count and count[0] >= 10) or db.execute("SELECT COUNT(*) FROM identity_grants").fetchone()[0] >= 256:
            store._event(db, "identity-grant-throttled", username)
            return None
        db.execute("INSERT INTO login_limits VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1", (key, now))
        token, instance = secrets.token_urlsafe(32), db.execute("SELECT instance FROM identity").fetchone()[0]
        session_end = min(now + store.SESSION_SECONDS, expires if expires is not None else now + store.SESSION_SECONDS)
        if session_end <= now:
            return None
        db.execute("INSERT INTO identity_grants VALUES(?,?,?,?,?,?,?,?,?,?)", (store._token_hash(token), user["id"], user["version"], instance,
            now, min(now + 300, session_end), session_end, 0, source, policy["fingerprint"]))
        store._event(db, "identity-first-factor-verified", username, source=source)
        return token, user["role"] in policy["data"]["mfa_roles"]


def finish(database, policy, token, code=None):
    now = time.time()
    with store.database(database, write=True) as db:
        grant = db.execute("SELECT * FROM identity_grants WHERE token_hash=?", (store._token_hash(token),)).fetchone()
        if grant is None:
            store._event(db, "mfa-grant-denied", "unknown-grant")
            return None
        user = db.execute("SELECT * FROM operators WHERE id=?", (grant["user_id"],)).fetchone()
        instance = db.execute("SELECT instance FROM identity").fetchone()[0]
        if (not user or not user["active"] or user["version"] != grant["version"] or grant["instance"] != instance
                or grant["fingerprint"] != policy["fingerprint"] or not grant["created"] <= now < grant["expires"]
                or grant["attempts"] >= 5):
            db.execute("DELETE FROM identity_grants WHERE token_hash=?", (grant["token_hash"],))
            store._event(db, "mfa-grant-denied", "expired-or-changed")
            return None
        required = user["role"] in policy["data"]["mfa_roles"]
        if required:
            factor = db.execute("SELECT * FROM operator_factors WHERE user_id=?", (user["id"],)).fetchone()
            secret = unseal(policy["key"], "totp:" + instance + ":" + str(user["id"]), factor["secret_cipher"]) if factor else None
            step = matched_step(secret, code, now, factor["last_step"]) if factor else None
            if step is None:
                db.execute("UPDATE identity_grants SET attempts=attempts+1 WHERE token_hash=?", (grant["token_hash"],))
                store._event(db, "mfa-code-denied", user["username"], source=grant["source"])
                return None
            db.execute("UPDATE operator_factors SET last_step=? WHERE user_id=?", (step, user["id"]))
        db.execute("DELETE FROM identity_grants WHERE token_hash=?", (grant["token_hash"],))
        db.execute("DELETE FROM operator_sessions WHERE expires<=?", (now,))
        old = db.execute("SELECT token_hash FROM operator_sessions WHERE user_id=? ORDER BY issued DESC LIMIT -1 OFFSET 7", (user["id"],)).fetchall()
        for row in old:
            db.execute("DELETE FROM operator_sessions WHERE token_hash=?", (row[0],))
        final = secrets.token_urlsafe(32)
        db.execute("INSERT INTO operator_sessions VALUES(?,?,?,?,?)", (store._token_hash(final), user["id"], user["version"], now, grant["session_expires"]))
        store._event(db, "identity-login-succeeded", user["username"], source=grant["source"], mfa=required)
        return final, instance


def setup(workspace_config, origin, *, authorized=False):
    if authorized is not True:
        raise PermissionError("Identity setup requires --authorized")
    from . import workspace
    path = store._path(workspace_config)
    data = _decode_json(read_bounded(path, 32768))
    if data.get("auth_config") is not None or data.get("oidc_config") is not None:
        raise ValueError("Review an existing authentication configuration instead of overwriting it")
    _origin(origin)
    workspace.load(path)
    key, config = path.parent / "auth.key", path.parent / "identity.json"
    if key.exists() or config.exists():
        raise FileExistsError("Choose a clean identity setup; existing keys/policy are preserved")
    value = {"schema_version": 1, "local_enabled": True, "mfa_roles": ["admin"], "key_file": str(key),
        "callback_origin": origin, "providers": {"google": {"enabled": False}, "entra": {"enabled": False}}}
    store.create_session_key(key, authorized=True)
    fd = os.open(config, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    data["auth_config"] = str(config)
    temporary = path.parent / ("identity-setup-" + secrets.token_hex(12) + ".tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(data, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    store.audit_event(path.parent / "operators.sqlite3", "os-admin-configured-unified-identity", data["workspace_id"])
    return {"policy_file": str(config), "key_file": str(key), "administrator_mfa_required": True,
        "enroll_mfa_before_startup": True, "secrets_displayed": False}


def enroll_cli(database, key_file, username, *, secret_stdin=False, authorized=False):
    import getpass
    import sys
    from urllib.parse import quote
    if authorized is not True:
        raise PermissionError("MFA enrollment requires --authorized")
    store._name(username)
    with store.database(database) as db:
        if not db.execute("SELECT id FROM operators WHERE username=?", (username,)).fetchone():
            raise ValueError("Only an approved existing account can enroll")
    confirmed = -1
    if secret_stdin:
        secret = sys.stdin.read(129).strip()
    else:
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise ValueError("Use a private terminal or explicitly pipe a secret using --secret-stdin")
        secret = base64.b32encode(secrets.token_bytes(20)).decode()
        uri = "otpauth://totp/" + quote("HunterQA:" + username, safe="") + "?secret=" + secret + "&issuer=HunterQA&digits=6&period=30"
        print("Add this private setup URI to your authenticator; it is shown only in this terminal:\n" + uri, file=sys.stderr)
        code = getpass.getpass("Current authenticator code: ", stream=sys.stderr)
        confirmed = matched_step(secret, code, time.time())
        if confirmed is None:
            raise ValueError("Authenticator confirmation failed; no enrollment saved")
    result = enroll(database, key_file, username, secret, authorized=True, confirmed_step=confirmed)
    result["secret_displayed"] = not secret_stdin
    return result
