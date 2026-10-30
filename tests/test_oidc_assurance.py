"""Real RS256 verification and fixed owned OIDC/session protocol controls."""
import base64
import hashlib
import json
import socket
import subprocess
import time
from urllib.parse import urlencode

import pytest

jwt = pytest.importorskip("jwt", reason="Optional identity extra")
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from hunterqa.cli import main
from hunterqa.oidc_tokens import pkce_challenge, validate_callback, verify_file, verify_id_token
from hunterqa import oidc_session_lab as lab


def raw_signed(key, header, payload):
    def segment(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=")
    message = segment(json.dumps(header).encode()) + b"." + segment(payload)
    return (message + b"." + segment(key.sign(message, padding.PKCS1v15(), hashes.SHA256()))).decode()


@pytest.fixture(scope="module")
def keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, other, {"keys": [lab._public_key(key)]}


@pytest.fixture
def sample(keys):
    key, _, jwks = keys
    now = int(time.time())
    policy = {"schema_version": 1, "issuer": "https://issuer.example.test/realm", "client_id": "private-client",
        "expected_nonce": "nonce_private_0123456789", "max_lifetime_seconds": 300, "max_age_seconds": 300,
        "expected_subject": "private-subject", "expected_tenant": "private-tenant", "allow_loopback_issuer": False}
    claims = {"iss": policy["issuer"], "aud": policy["client_id"], "sub": policy["expected_subject"],
        "tenant_id": policy["expected_tenant"], "nonce": policy["expected_nonce"], "iat": now, "exp": now + 120}
    def sign(values=None, headers=None, signing_key=None, algorithm="RS256"):
        return jwt.encode(values if values is not None else claims, signing_key or key,
                          algorithm=algorithm, headers={"kid": "fixture-key", **(headers or {})})
    return policy, claims, jwks, sign


def test_actual_signature_and_policy_verification_has_no_network_or_secret_exports(sample, monkeypatch):
    policy, _, jwks, sign = sample
    token = sign()
    def forbidden(*args, **kwargs):
        pytest.fail("Offline signature verification performed network/subprocess work")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    report = verify_id_token(token, jwks, policy)
    assert report["accepted"] and report["signature_and_policy_verified"]
    assert report["network_requests"] == 0 and report["server_acceptance_verified"] is False
    assert report["tenant_isolation_verified"] is False
    for value in (token, policy["issuer"], policy["expected_nonce"], policy["expected_subject"], policy["expected_tenant"]):
        assert value not in json.dumps(report)


@pytest.mark.parametrize("changes", [
    {"iss": "https://issuer.example.test"}, {"iss": "https://issuer.example.test/realm/extra"},
    {"aud": "other-client"}, {"aud": ["private-client", "other"]},
    {"aud": ["private-client", "private-client"]}, {"aud": [True]},
    {"azp": "other-client"}, {"sub": "other-subject"}, {"sub": True},
    {"tenant_id": "other-tenant"}, {"nonce": "other_nonce_0123456789"},
    {"nonce": "é" * 20}, {"iat": True}, {"exp": "9999999999"},
    {"nbf": True}, {"auth_time": False}, {"exp": float("nan")},
])
def test_signed_but_invalid_claims_fail_closed(sample, changes):
    policy, claims, jwks, sign = sample
    assert verify_id_token(sign({**claims, **changes}), jwks, policy)["accepted"] is False


@pytest.mark.parametrize("case", ["expired", "future-iat", "future-nbf", "stale", "long-lived", "auth-time"])
def test_current_time_and_lifetime_constraints(sample, case):
    policy, claims, jwks, sign = sample
    now = int(time.time())
    changes = {"expired": {"iat": now - 100, "exp": now - 1},
        "future-iat": {"iat": now + 60, "exp": now + 120}, "future-nbf": {"nbf": now + 60},
        "stale": {"iat": now - 400, "exp": now + 1}, "long-lived": {"exp": now + 400},
        "auth-time": {"auth_time": now + 60}}[case]
    if case == "stale":
        policy = {**policy, "max_lifetime_seconds": 1000}
    assert not verify_id_token(sign({**claims, **changes}), jwks, policy)["accepted"]


def test_multi_audience_requires_exact_authorized_party_and_optional_binding_is_explicit(sample):
    policy, claims, jwks, sign = sample
    values = {**claims, "aud": [policy["client_id"], "other"], "azp": policy["client_id"]}
    assert verify_id_token(sign(values), jwks, policy)["accepted"]
    values.update(sub="different-subject", tenant_id="b")
    report = verify_id_token(sign(values), jwks, {**policy, "expected_subject": None, "expected_tenant": None})
    assert report["accepted"] and not report["subject_binding_checked"] and not report["tenant_claim_binding_checked"]


@pytest.mark.parametrize("header", [{"kid": "untrusted"}, {"typ": "at+jwt"}, {"crit": []},
    {"b64": True}, {"jku": "https://evil.example.test/key"}, {"x5u": "file:///private-key"}, {"x5c": []}])
def test_headers_cannot_select_remote_keys_or_another_token_type(sample, keys, header, monkeypatch):
    policy, claims, jwks, _ = sample
    token = raw_signed(keys[0], {"alg": "RS256", "typ": "JWT", "kid": "fixture-key", **header}, json.dumps(claims).encode())
    monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: pytest.fail("Remote key retrieval"))
    assert not verify_id_token(token, jwks, policy)["accepted"]


def test_bad_signature_and_symmetric_algorithm_confusion_are_rejected(sample, keys):
    policy, claims, jwks, sign = sample
    assert not verify_id_token(sign(signing_key=keys[1]), jwks, policy)["accepted"]
    token = jwt.encode(claims, "synthetic-hmac-key-with-at-least-32-bytes", algorithm="HS256", headers={"kid": "fixture-key"})
    assert not verify_id_token(token, jwks, policy)["accepted"]
    token = jwt.encode(claims, "", algorithm="none", headers={"kid": "fixture-key"})
    assert not verify_id_token(token, jwks, policy)["accepted"]


def test_duplicate_claims_and_noncanonical_segments_are_rejected(sample, keys):
    policy, claims, jwks, _ = sample
    payload = json.dumps(claims).rstrip("}") + ',"iss":"' + policy["issuer"] + '"}'
    token = raw_signed(keys[0], {"alg": "RS256", "kid": "fixture-key", "typ": "JWT"}, payload.encode())
    assert not verify_id_token(token, jwks, policy)["accepted"]
    assert not verify_id_token(token + "=", jwks, policy)["accepted"]


@pytest.mark.parametrize("changes", [{"d": "private-key-material"}, {"alg": "HS256"}, {"use": "enc"},
    {"key_ops": ["sign"]}, {"e": "Aw"}, {"n": "https://evil.example.test/key"}])
def test_only_bounded_rsa_public_verification_keys_are_accepted(sample, changes):
    policy, _, jwks, sign = sample
    changed = {"keys": [{**jwks["keys"][0], **changes}]}
    with pytest.raises(ValueError):
        verify_id_token(sign(), changed, policy)


def test_duplicate_key_ids_and_weak_rsa_modulus_are_rejected(sample):
    policy, _, jwks, sign = sample
    with pytest.raises(ValueError):
        verify_id_token(sign(), {"keys": jwks["keys"] * 2}, policy)
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(ValueError):
        verify_id_token(sign(), {"keys": [lab._public_key(weak)]}, policy)


@pytest.mark.parametrize("changes", [{"issuer": "http://public.example.test/", "allow_loopback_issuer": True},
    {"issuer": "https://user:private@issuer.example.test/"}, {"issuer": "https://issuer.example.test:private"},
    {"issuer": "https://issuer.example.test/?query=private"}, {"max_age_seconds": True},
    {"max_lifetime_seconds": 86401}, {"expected_nonce": "short"}, {"allow_loopback_issuer": "true"}])
def test_invalid_policy_is_not_reported_as_a_valid_token_test(sample, changes):
    policy, _, jwks, sign = sample
    with pytest.raises(ValueError) as error:
        verify_id_token(sign(), jwks, {**policy, **changes})
    assert policy["expected_subject"] not in str(error.value)
    assert policy["expected_nonce"] not in str(error.value)


def test_pkce_matches_rfc_7636_vector():
    assert pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    with pytest.raises(ValueError):
        pkce_challenge("short")


@pytest.mark.parametrize("suffix", ["?code=code_value&state=wrong_state", "?code=x&state=x&state=x",
    "?code=x&state=x&extra=y", "?code=x&state=x#fragment", "?error=denied", "?code=%0A&state=x"])
def test_callbacks_require_exact_uri_and_unique_correlated_state(suffix):
    callback = "https://client.example.test/callback"
    with pytest.raises(ValueError):
        validate_callback(callback + suffix, callback, "state_0123456789abcdef")
    state = "state_0123456789abcdef"
    assert validate_callback(callback + "?" + urlencode({"code": "opaque_code", "state": state}), callback, state) == "opaque_code"
    with pytest.raises(ValueError):
        validate_callback("https://other.example.test/callback?" + urlencode({"code": "opaque", "state": state}), callback, state)


def test_private_file_cli_is_create_only_and_withholds_token_claims(sample, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    policy, _, jwks, sign = sample
    path, out = tmp_path / "token-input.json", tmp_path / "verification.json"
    path.write_text(json.dumps({"schema_version": 1, "token": sign(), "jwks": jwks, "policy": policy}))
    main(["signed-id-token-verify", "--input", str(path), "--out", str(out)])
    assert json.loads(out.read_text())["accepted"]
    assert "private-subject" not in out.read_text()
    with pytest.raises(FileExistsError):
        main(["signed-id-token-verify", "--input", str(path), "--out", str(out)])
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS")
    with pytest.raises(ValueError):
        verify_file(path)


def test_owned_protocol_and_session_boundaries_have_independent_labels(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    generated = []
    def synthetic_secret(*args):
        value = hashlib.sha256(str(len(generated)).encode()).hexdigest()
        generated.append(value)
        return value
    monkeypatch.setattr(lab.secrets, "token_urlsafe", synthetic_secret)
    root = tmp_path / "owned-identity"
    report = lab.benchmark(root, authorized=True)
    assert report["all_cases_matched"] and len(report["cases"]) == 18 and report["network_requests"] == 22
    assert sum(m["true_positives"] for m in report["by_class"].values()) == 5
    assert sum(m["false_positives"] + m["false_negatives"] for m in report["by_class"].values()) == 0
    retained = "".join(p.read_text() for p in root.glob("*.json"))
    assert all(secret not in retained for secret in generated)
    assert lab.SEED not in retained and "fixture-user-a" not in retained and '"access_token"' not in retained
    monkeypatch.setattr(lab, "HTTPConnection", lambda *a, **kw: pytest.fail("Offline verification sent traffic"))
    assert lab.verify(root)["passed"]
    changed = json.loads((root / "weak.json").read_text())
    changed["checks"]["pkce-verifier"] = True
    (root / "weak.json").write_text(json.dumps(changed))
    with pytest.raises(ValueError):
        lab.verify(root)
    with pytest.raises(FileExistsError):
        lab.benchmark(root, authorized=True)


def test_owned_authorization_and_measurement_do_not_hide_missed_faults(tmp_path):
    with pytest.raises(PermissionError):
        lab.benchmark(tmp_path / "not-authorized")
    assert not (tmp_path / "not-authorized").exists()
    labels = json.loads(lab.LABELS.read_bytes())
    rows = [{"variant": v, "checks": {c["id"]: c[v] for c in labels["checks"]}} for v in ("secure", "weak")]
    rows[1]["checks"]["pkce-verifier"] = True
    rows[0]["checks"]["logout-revocation"] = False
    result = lab.measure(labels, rows)
    assert result["by_class"]["pkce"]["false_negatives"] == 1
    assert result["by_class"]["session"]["false_positives"] == 1
    assert not result["all_cases_matched"]
    rows[1]["checks"]["pkce-verifier"] = None
    score = lab.measure(labels, rows)["by_class"]["pkce"]
    assert score["inconclusive_positive"] == 1 and score["positive_miss_rate"] == 1
