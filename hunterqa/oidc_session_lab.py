"""Owned OIDC/session HTTP fixture. No external issuer, account or target input."""
import base64
from contextlib import contextmanager
import hashlib
import hmac
from http.client import HTTPConnection
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import PackageNotFoundError, version
import json
from pathlib import Path
import re
import secrets
from threading import RLock, Thread
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

from .bounty import _read_json
from .engagement import digest, utcnow
from .oidc_tokens import _engine, _json, pkce_challenge, validate_callback, verify_id_token
from .workflow_runner import _runtime_identity
from .workflow_store import approved_directory, private_write

LABELS = Path(__file__).parent / "fixtures" / "oidc-session-v1.json"
CLIENT = "hunterqa-public-fixture"
SEED = "hunterqaFixedSyntheticSession"
CANARIES = {"a": "HUNTERQA_PUBLIC_TENANT_A", "b": "HUNTERQA_PUBLIC_TENANT_B"}


def _identity():
    packages = {}
    for name in ("PyJWT", "cryptography"):
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            packages[name] = None
    return digest({"sources": _runtime_identity(), "identity_packages": packages})


def _public_key(key):
    numbers = key.public_key().public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "kid": "fixture-key", "alg": "RS256", "use": "sig",
            "n": base64.urlsafe_b64encode(n).decode().rstrip("="), "e": "AQAB"}


def _form(raw, limit=10):
    pairs = parse_qsl(raw, strict_parsing=True, keep_blank_values=True, max_num_fields=limit)
    if len(dict(pairs)) != len(pairs) or any(len(k) > 64 or len(v) > 2048 for k, v in pairs):
        raise ValueError("Ambiguous fixture form")
    return dict(pairs)


@contextmanager
def owned_issuer():
    jwt = _engine()
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {"keys": [_public_key(key)]}
    store, lock = {"codes": {}, "tokens": {}, "sessions": {}, "requests": 0}, RLock()
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def log_message(self, *args):
            pass

        def reply(self, status, body, headers=()):
            raw = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def serve(self):
            parts = urlsplit(self.path)
            split = parts.path.strip("/").split("/")
            if len(split) != 2 or split[0] not in {"secure", "weak"}:
                self.reply(404, {"error": "unknown_fixture_route"})
                return
            mode, endpoint = split
            issuer = f"http://127.0.0.1:{self.server.server_port}/{mode}"
            callback = f"http://127.0.0.1:{self.server.server_port}/callback"
            if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
                raise ValueError("Host differs")
            if self.command == "POST":
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 8192 or self.headers.get("Content-Type") != "application/x-www-form-urlencoded":
                    raise ValueError("Invalid fixture body")
                fields = _form(self.rfile.read(length).decode("utf-8"))
            else:
                fields = _form(parts.query)
            if endpoint == "jwks" and self.command == "GET" and not fields:
                self.reply(200, jwks)
            elif endpoint == "authorize" and self.command == "GET":
                if (set(fields) != {"scope", "response_type", "client_id", "redirect_uri", "state", "nonce", "code_challenge", "code_challenge_method"}
                        or fields["scope"] != "openid"
                        or fields["response_type"] != "code" or fields["client_id"] != CLIENT
                        or fields["redirect_uri"] != callback or fields["code_challenge_method"] != "S256"):
                    raise ValueError("Unsupported fixture authorization")
                code = secrets.token_urlsafe(32)
                store["codes"][code] = {"mode": mode, **fields, "used": False, "expires": time.time() + 60}
                self.reply(302, {}, [("Location", callback + "?" + urlencode({"code": code, "state": fields["state"]}))])
            elif endpoint == "token" and self.command == "POST":
                if set(fields) != {"grant_type", "client_id", "redirect_uri", "code", "code_verifier"} or fields["grant_type"] != "authorization_code":
                    raise ValueError("Unsupported fixture token request")
                code = store["codes"].get(fields["code"])
                if (not code or code["mode"] != mode or code["expires"] <= time.time()
                        or fields["client_id"] != CLIENT or fields["redirect_uri"] != callback
                        or (mode == "secure" and (code["used"] or not hmac.compare_digest(
                            pkce_challenge(fields["code_verifier"]), code["code_challenge"])))):
                    self.reply(400, {"error": "invalid_grant"})
                    return
                code["used"] = True
                now = int(time.time())
                token = jwt.encode({"iss": issuer, "aud": CLIENT, "sub": "fixture-user-a",
                    "tenant_id": "a", "iat": now, "exp": now + 120, "nonce": code["nonce"]},
                    key, algorithm="RS256", headers={"kid": "fixture-key"})
                access = secrets.token_urlsafe(32)
                store["tokens"][access] = {"mode": mode, "tenant": "a"}
                self.reply(200, {"id_token": token, "access_token": access, "token_type": "Bearer"})
            elif endpoint == "session" and self.command == "POST" and not fields:
                authorization = self.headers.get("Authorization", "")
                identity = store["tokens"].get(authorization.removeprefix("Bearer ")) if authorization.startswith("Bearer ") else None
                if not identity or identity["mode"] != mode:
                    self.reply(401, {"error": "unauthorized"})
                    return
                cookies = SimpleCookie(self.headers.get("Cookie", ""))
                session = cookies["hq_session"].value if mode == "weak" and "hq_session" in cookies else secrets.token_urlsafe(32)
                store["sessions"][(mode, session)] = "a"
                self.reply(200, {"session_created": True}, [("Set-Cookie", "hq_session=" + session + "; HttpOnly; SameSite=Strict; Path=/")])
            elif endpoint in {"resource", "logout"}:
                cookies = SimpleCookie(self.headers.get("Cookie", ""))
                session = cookies["hq_session"].value if "hq_session" in cookies else ""
                tenant = store["sessions"].get((mode, session))
                if endpoint == "logout" and self.command == "POST" and not fields:
                    if mode == "secure":
                        store["sessions"].pop((mode, session), None)
                    self.reply(200, {"logged_out": True})
                elif endpoint == "resource" and self.command == "GET" and set(fields) == {"tenant"} and fields["tenant"] in CANARIES:
                    if tenant is None:
                        self.reply(401, {"error": "unauthorized"})
                    elif mode == "secure" and fields["tenant"] != tenant:
                        self.reply(403, {"error": "forbidden"})
                    else:
                        self.reply(200, {"canary": CANARIES[fields["tenant"]]})
                else:
                    raise ValueError("Invalid fixture action")
            else:
                raise ValueError("Invalid fixture endpoint")

        def dispatch(self):
            with lock:
                store["requests"] += 1
                try:
                    self.serve()
                except (ValueError, KeyError, UnicodeError):
                    self.reply(400, {"error": "invalid_request"})

        do_GET = dispatch
        do_POST = dispatch
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, store
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _request(port, mode, endpoint, receipts, *, method="GET", fields=None, headers=None):
    if mode not in {"secure", "weak"} or endpoint not in {"jwks", "authorize", "token", "session", "resource", "logout"}:
        raise ValueError("Unknown fixed fixture request")
    path = f"/{mode}/{endpoint}"
    outgoing, body = dict(headers or {}), None
    if method == "GET" and fields:
        path += "?" + urlencode(fields)
    elif method == "POST":
        body = urlencode(fields or {}).encode()
        outgoing["Content-Type"] = "application/x-www-form-urlencoded"
    connection = HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request(method, path, body=body, headers=outgoing)
        response = connection.getresponse()
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("Fixture response exceeded size limit")
        receipts.append({"method": method, "endpoint": endpoint, "status": response.status,
                         "body_sha256": hashlib.sha256(raw).hexdigest(), "body_bytes": len(raw)})
        return response.status, dict(response.getheaders()), _json(raw)
    finally:
        connection.close()


def _policy(issuer, nonce):
    return {"schema_version": 1, "issuer": issuer, "client_id": CLIENT, "expected_nonce": nonce,
            "max_lifetime_seconds": 300, "max_age_seconds": 300, "expected_subject": "fixture-user-a",
            "expected_tenant": "a", "allow_loopback_issuer": True}


def exercise(port, mode):
    receipts, checks = [], {}
    callback = f"http://127.0.0.1:{port}/callback"
    def request(endpoint, **kwargs):
        return _request(port, mode, endpoint, receipts, **kwargs)
    def authorize(verifier, state, nonce):
        status, headers, _ = request("authorize", fields={"scope": "openid", "response_type": "code", "client_id": CLIENT,
            "redirect_uri": callback, "state": state, "nonce": nonce,
            "code_challenge": pkce_challenge(verifier), "code_challenge_method": "S256"})
        if status != 302:
            raise ValueError("Owned authorization control failed")
        return headers["Location"]
    def exchange(code, verifier):
        return request("token", method="POST", fields={"grant_type": "authorization_code", "client_id": CLIENT,
            "redirect_uri": callback, "code": code, "code_verifier": verifier})
    status, _, jwks = request("jwks")
    if status != 200:
        raise ValueError("Owned public-key control failed")
    verifier, state, nonce = (secrets.token_urlsafe(32) for _ in range(3))
    location = authorize(verifier, state, nonce)
    try:
        validate_callback(location, callback, "wrong" + state)
        checks["callback-state"] = False
    except ValueError:
        checks["callback-state"] = True
    code = validate_callback(location, callback, state)
    status, _, tokens = exchange(code, verifier)
    policy = _policy(f"http://127.0.0.1:{port}/{mode}", nonce)
    verification = verify_id_token(tokens["id_token"], jwks, policy) if status == 200 else {"accepted": False}
    checks["signed-id-token"] = verification["accepted"]
    if not verification["accepted"]:
        raise ValueError("Owned signed-token control failed")
    def token_guard(status, response):
        if status == 400 and response.get("error") == "invalid_grant":
            return True
        if status == 200 and isinstance(response.get("id_token"), str):
            return False if verify_id_token(response["id_token"], jwks, policy)["accepted"] else None
        return None
    checks["nonce-binding"] = not verify_id_token(tokens["id_token"], jwks, {**policy, "expected_nonce": "wrong" + nonce})["accepted"]
    replay_status, _, replay = exchange(code, verifier)
    checks["code-single-use"] = token_guard(replay_status, replay)
    second = validate_callback(authorize(verifier, state, nonce), callback, state)
    pkce_status, _, wrong = exchange(second, secrets.token_urlsafe(32))
    checks["pkce-verifier"] = token_guard(pkce_status, wrong)
    status, headers, _ = request("session", method="POST", headers={
        "Authorization": "Bearer " + tokens["access_token"], "Cookie": "hq_session=" + SEED})
    if status != 200:
        raise ValueError("Owned session control failed")
    cookies = SimpleCookie(headers["Set-Cookie"])
    session = cookies["hq_session"].value
    cookie = {"Cookie": "hq_session=" + session}
    own_status, _, own = request("resource", fields={"tenant": "a"}, headers=cookie)
    own_ok = own_status == 200 and own.get("canary") == CANARIES["a"]
    checks["own-tenant-access"] = own_ok
    if not own_ok:
        raise ValueError("Owned authenticated canary control failed")
    checks["session-rotation"] = not hmac.compare_digest(session, SEED)
    foreign_status, _, foreign = request("resource", fields={"tenant": "b"}, headers=cookie)
    checks["cross-tenant-boundary"] = (True if foreign_status == 403 and "canary" not in foreign else
        False if foreign_status == 200 and foreign.get("canary") == CANARIES["b"] else None)
    logout_status, _, _ = request("logout", method="POST", headers=cookie)
    after_status, _, after = request("resource", fields={"tenant": "a"}, headers=cookie)
    checks["logout-revocation"] = (True if logout_status == 200 and after_status == 401 and "canary" not in after else
        False if logout_status == 200 and after_status == 200 and after.get("canary") == CANARIES["a"] else None)
    return {"variant": mode, "checks": checks, "receipts": receipts,
            "signed_token_receipt": verification, "network_requests": len(receipts)}


def measure(labels, results):
    if (not isinstance(results, list) or len(results) != 2 or any(not isinstance(r, dict) for r in results)
            or [r.get("variant") for r in results] != ["secure", "weak"]):
        raise ValueError("Expected both owned variants")
    cases, scores = [], {}
    for result in results:
        if set(result.get("checks", {})) != {c["id"] for c in labels["checks"]}:
            raise ValueError("Missing owned identity check")
        for label in labels["checks"]:
            actual = result["checks"][label["id"]]
            if actual is not None and type(actual) is not bool:
                raise ValueError("Invalid owned identity observation")
            expected = label[result["variant"]]
            cases.append({"id": result["variant"] + ":" + label["id"], "matched": actual is expected})
            score = scores.setdefault(label["class"], {"true_positives": 0, "false_positives": 0,
                "false_negatives": 0, "true_negatives": 0, "inconclusive": 0,
                "inconclusive_positive": 0, "inconclusive_negative": 0})
            if actual is None:
                score["inconclusive"] += 1
                score["inconclusive_negative" if expected else "inconclusive_positive"] += 1
            else:
                key = ("false_negatives" if actual else "true_positives") if not expected else (
                    "true_negatives" if actual else "false_positives")
                score[key] += 1
    for score in scores.values():
        tp, fp, fn, tn = (score[k] for k in ("true_positives", "false_positives", "false_negatives", "true_negatives"))
        positives = tp + fn + score["inconclusive_positive"]
        score.update(precision=tp / (tp + fp) if tp + fp else None,
                     recall=tp / (tp + fn) if tp + fn else None,
                     false_positive_rate=fp / (fp + tn) if fp + tn else None,
                     false_negative_rate=fn / (tp + fn) if tp + fn else None,
                     positive_miss_rate=(fn + score["inconclusive_positive"]) / positives if positives else None)
    return {"cases": cases, "by_class": scores, "all_cases_matched": all(c["matched"] for c in cases)}


def benchmark(out_dir, *, authorized=False):
    if not authorized:
        raise PermissionError("Owned OIDC/session benchmark requires --authorized")
    _engine()
    root = Path(out_dir).expanduser().absolute()
    approved_directory(root.parent)
    root.mkdir(mode=0o700)
    labels = json.loads(LABELS.read_bytes())
    private_write(root / "ground-truth.json", labels)
    results = []
    with owned_issuer() as (port, store):
        for variant in ("secure", "weak"):
            result = exercise(port, variant)
            private_write(root / (variant + ".json"), result)
            results.append(result)
        served = store["requests"]
    if served != sum(r["network_requests"] for r in results):
        raise ValueError("Owned identity request counts differ")
    report = {"engine": "hunterqa_owned_oidc_session_benchmark", "schema_version": 1,
        "generated_at": utcnow().isoformat(), "fixture_version": labels["fixture_version"],
        "source_identity_sha256": _identity(), "labels_sha256": hashlib.sha256(LABELS.read_bytes()).hexdigest(),
        "result_sha256": {r["variant"]: digest(r) for r in results}, **measure(labels, results),
        "network_requests": served, "real_world_effectiveness": "unverified", "customer_findings_confirmed": 0,
        "limitations": ["Fixed local HTTP issuer/client simulation with synthetic auto-authorization; no external SSO login or consent",
            "Five deliberately weak guard cases, not representative identity or tenant-isolation coverage",
            "Synthetic HTTP cookies do not establish production HTTPS/cookie policy or OS isolation",
            "No ID/access tokens, session cookies, codes, verifiers, nonces or user claims exported",
            "Supplied-key verification does not independently authenticate a real issuer; hashes are local consistency only"]}
    private_write(root / "benchmark.json", report)
    return report


def verify(directory):
    root = approved_directory(directory)
    report = _read_json(root / "benchmark.json", 100_000)
    labels = json.loads(LABELS.read_bytes())
    if (not isinstance(report, dict) or report.get("engine") != "hunterqa_owned_oidc_session_benchmark"
            or type(report.get("schema_version")) is not int or report["schema_version"] != 1
            or report.get("source_identity_sha256") != _identity()
            or report.get("labels_sha256") != hashlib.sha256(LABELS.read_bytes()).hexdigest()
            or report.get("fixture_version") != labels["fixture_version"]
            or _read_json(root / "ground-truth.json", 100_000) != labels
            or type(report.get("customer_findings_confirmed")) is not int or report["customer_findings_confirmed"] != 0
            or report.get("real_world_effectiveness") != "unverified"):
        raise ValueError("Owned identity evidence is stale, inconsistent or overstated")
    results = [_read_json(root / (v + ".json"), 100_000) for v in ("secure", "weak")]
    for result in results:
        if not isinstance(result, dict) or set(result) != {"variant", "checks", "receipts", "signed_token_receipt", "network_requests"}:
            raise ValueError("Invalid owned identity result fields")
        receipts = result.get("receipts")
        if (not isinstance(receipts, list) or len(receipts) != 11 or type(result.get("network_requests")) is not int
                or result["network_requests"] != 11
                or report.get("result_sha256", {}).get(result.get("variant")) != digest(result)):
            raise ValueError("Invalid owned identity receipt binding")
        sequence = [("GET", "jwks"), ("GET", "authorize"), ("POST", "token"), ("POST", "token"),
                    ("GET", "authorize"), ("POST", "token"), ("POST", "session"), ("GET", "resource"),
                    ("GET", "resource"), ("POST", "logout"), ("GET", "resource")]
        for receipt, (method, endpoint) in zip(receipts, sequence):
            if (not isinstance(receipt, dict) or set(receipt) != {"method", "endpoint", "status", "body_sha256", "body_bytes"}
                    or receipt["method"] != method or receipt["endpoint"] != endpoint
                    or type(receipt["status"]) is not int or not 100 <= receipt["status"] <= 599
                    or type(receipt["body_bytes"]) is not int or not 0 <= receipt["body_bytes"] <= 65536
                    or not isinstance(receipt["body_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", receipt["body_sha256"])):
                raise ValueError("Invalid owned identity HTTP receipt")
        token = result["signed_token_receipt"]
        if (not isinstance(token, dict) or token.get("engine") != "hunterqa_signed_id_token_verification"
                or any(token.get(k) is not True for k in ("accepted", "signature_and_policy_verified",
                        "subject_binding_checked", "tenant_claim_binding_checked"))
                or any(token.get(k) is not False for k in ("server_acceptance_verified", "tenant_isolation_verified", "access_token_binding_verified"))
                or token.get("key_anchor_trust") != "owner_supplied_unverified"
                or type(token.get("network_requests")) is not int or token["network_requests"] != 0
                or result["checks"].get("signed-id-token") is not True):
            raise ValueError("Invalid retained signed-token receipt")
    measured = measure(labels, results)
    if (any(digest(report.get(k)) != digest(v) for k, v in measured.items())
            or type(report.get("network_requests")) is not int or report["network_requests"] != 22):
        raise ValueError("Owned identity metrics differ from retained observations")
    return {"status": "retained_consistency_checked", "passed": measured["all_cases_matched"], **measured,
            "network_requests": 0, "tokens_reverified": False, "fresh_validation_performed": False,
            "real_world_effectiveness": "unverified", "trust": "Local consistency only; rerun for fresh identity/session checks"}
