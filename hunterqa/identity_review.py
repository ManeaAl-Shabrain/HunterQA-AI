"""Offline JWT/OAuth evidence review; no token verification, signing or traffic."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 256 * 1024
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
ALGORITHMS = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red#auth--identity",
    "https://www.rfc-editor.org/rfc/rfc8725.html", "https://www.rfc-editor.org/rfc/rfc9700.html"]


def catalog():
    return [{"id": "offensive-jwt", "implementation": "offline-sample-policy-review",
        "active_exploitation_available": False, "cryptographic_verification_available": False,
        "separate_signature_command": "signed-id-token-verify (RS256 ID tokens; optional identity extra)",
        "required_evidence": "Private compact JWS samples and independently selected issuer, audience and algorithm policy; server acceptance and signature validation require independent tests"},
        {"id": "offensive-oauth", "implementation": "offline-web-client-configuration-review",
        "active_exploitation_available": False,
        "required_evidence": "Owner-provided web client configuration; verify actual PKCE, redirect, CSRF, nonce, session and token handling independently"}]


def _json(raw):
    def pairs(entries):
        result = {}
        for key, value in entries:
            if key in result:
                raise ValueError("Duplicate key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("Non-finite JSON number")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid or unsupported identity JSON; contents withheld") from None


def _fields(data, names):
    if not isinstance(data, dict) or set(data) != set(names):
        raise ValueError("Identity evidence has missing or unknown fields; contents withheld")


def _text(value):
    return isinstance(value, str) and 0 < len(value) <= 2048 and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def _strings(value, maximum=20):
    return isinstance(value, list) and len(value) <= maximum and all(_text(v) for v in value) and len(set(value)) == len(value)


def validate_evidence(data):
    _fields(data, ("schema_version", "jwt_samples", "oauth_clients"))
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported identity schema version")
    if not all(isinstance(data[k], list) and len(data[k]) <= 10 for k in ("jwt_samples", "oauth_clients")) or not (data["jwt_samples"] or data["oauth_clients"]):
        raise ValueError("Select 1..20 total cases, at most 10 per skill")
    ids = set()
    for row in data["jwt_samples"] + data["oauth_clients"]:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not ID.fullmatch(row["id"]) or row["id"] in ids:
            raise ValueError("Identity case IDs must be distinct lowercase identifiers")
        ids.add(row["id"])
    for row in data["jwt_samples"]:
        _fields(row, ("id", "token", "allowed_algorithms", "expected_issuer", "expected_audience"))
        if not isinstance(row["token"], str) or not 1 <= len(row["token"]) <= 16384:
            raise ValueError("JWT sample exceeds supported bounds")
        if not _strings(row["allowed_algorithms"]) or not row["allowed_algorithms"] or not set(row["allowed_algorithms"]) <= ALGORITHMS:
            raise ValueError("Select an explicit supported signing-algorithm policy")
        if not all(_text(row[key]) for key in ("expected_issuer", "expected_audience")):
            raise ValueError("JWT samples require explicit issuer and audience expectations")
    for row in data["oauth_clients"]:
        _fields(row, ("id", "client_type", "oidc", "issuer", "authorization_endpoint", "token_endpoint", "redirect_uris", "response_types", "grant_types", "pkce_required", "pkce_methods", "state_required", "nonce_required", "redirect_matching"))
        if row["client_type"] not in ("public", "confidential") or row["redirect_matching"] not in ("exact", "prefix", "wildcard"):
            raise ValueError("Unsupported web-client policy choice")
        if not all(type(row[k]) is bool for k in ("oidc", "pkce_required", "state_required", "nonce_required")):
            raise ValueError("Identity policy flags must be booleans")
        if not all(_text(row[k]) for k in ("issuer", "authorization_endpoint", "token_endpoint")):
            raise ValueError("Expected bounded endpoint strings")
        if not all(_strings(row[k]) for k in ("redirect_uris", "response_types", "grant_types", "pkce_methods")) or not row["grant_types"]:
            raise ValueError("Expected bounded nonduplicate policy lists")
        if not set(row["pkce_methods"]) <= {"S256", "plain"}:
            raise ValueError("Unsupported PKCE method declaration")
        if not all(set(t.split()) and set(t.split()) <= {"code", "token", "id_token"} for t in row["response_types"]):
            raise ValueError("Unsupported response type declaration")
        if not set(row["grant_types"]) <= {"authorization_code", "refresh_token", "client_credentials", "password", "implicit"}:
            raise ValueError("Unsupported web-client grant declaration")
        if (set(row["grant_types"]) & {"authorization_code", "implicit"} or row["response_types"]) and not (row["redirect_uris"] and row["response_types"]):
            raise ValueError("Redirect-based declarations require response types and registered redirect URIs")
    return data


def _segment(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Unsupported compact encoding")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise ValueError("Noncanonical compact encoding")
    return raw


def _jwt(row, now, add):
    def cue(key, title, fix, severity="WARNING"):
        add(row["id"], "jwt", key, title, fix, severity)
    try:
        parts = row["token"].split(".")
        if len(parts) != 3:
            raise ValueError("Unsupported token serialization")
        header, claims = (_json(_segment(p)) for p in parts[:2])
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise ValueError("Expected JSON objects")
        if parts[2]:
            _segment(parts[2])
    except (ValueError, UnicodeError):
        cue("unsupported-token", "JWT sample is malformed or outside supported compact JWS format", "Review the original private sample; encrypted JWE and detached/unencoded payloads are unsupported.", "INFO")
        return "unsupported-or-malformed"
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in row["allowed_algorithms"]:
        cue("algorithm-policy", "Unverified JWT algorithm differs from the selected policy", "Enforce an independently configured signing-algorithm allowlist at the verifier.")
    if alg == "none" or not parts[2]:
        cue("unsigned-sample", "JWT sample declares no signing or has an empty signature", "Reject unsigned authentication tokens; independently verify server behavior.")
    if any(k in header for k in ("jku", "x5u", "jwk")):
        cue("key-source", "JWT sample contains a key-source header", "Bind trusted keys independently of token-supplied URLs or inline keys; review retrieval policy.", "INFO")
    if "crit" in header or header.get("b64") is False:
        cue("header-extension", "JWT sample contains header extensions requiring separate review", "Use a verifier that explicitly handles or rejects required extensions.", "INFO")
    allowed = row["allowed_algorithms"]
    if any(a.startswith("HS") for a in allowed) and any(not a.startswith("HS") for a in allowed):
        cue("mixed-key-families", "Selected JWT policy combines symmetric and asymmetric algorithms", "Separate token validation contexts and key types; this observation does not prove confusion.", "INFO")
    dates = {}
    for name in ("exp", "nbf", "iat"):
        if name not in claims:
            if name == "exp":
                cue("expiry-missing", "JWT sample lacks expiration required by this review policy", "Require and validate expiration for tokens in this authentication context.")
            continue
        value = claims[name]
        if type(value) not in (int, float) or abs(value) > 100_000_000_000 or not math.isfinite(value):
            cue("invalid-" + name, "JWT sample has an unsupported temporal claim", "Require finite numeric dates and reject malformed temporal claims.")
            continue
        dates[name] = value
        if name == "exp" and value <= now:
            cue("expired-sample", "JWT sample has expired at the recorded review time", "Ensure the verifier rejects expired tokens; sample expiry alone does not prove server acceptance.", "INFO")
        if name in ("nbf", "iat") and value > now:
            cue("future-" + name, "JWT sample has a temporal claim later than review time", "Review clock policy and verifier handling; zero clock leeway is used in this offline comparison.", "INFO")
    if "exp" in dates and any(dates[k] > dates["exp"] for k in ("nbf", "iat") if k in dates):
        cue("date-order", "JWT sample has inconsistent temporal ordering", "Review issuance and validity policy and reject inconsistent tokens.")
    if claims.get("iss") != row["expected_issuer"]:
        cue("issuer-policy", "Unverified JWT issuer differs from the selected expectation", "Validate the exact expected issuer independently of untrusted token contents.")
    audience = claims.get("aud")
    if not (isinstance(audience, str) and audience == row["expected_audience"] or isinstance(audience, list) and audience and all(isinstance(a, str) for a in audience) and row["expected_audience"] in audience):
        cue("audience-policy", "Unverified JWT audience differs from the selected expectation", "Validate audience for the intended relying party and token context.")
    return "compact-jws"


def _https(value):
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if not host or "%" in host:
            return False
        try:
            ipaddress.ip_address(host)
        except ValueError:
            ascii_host = host.encode("idna").decode("ascii").rstrip(".")
            if len(ascii_host) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in ascii_host.split(".")):
                return False
        return parsed.scheme == "https" and parsed.username is None and parsed.password is None and not parsed.fragment and not any(c.isspace() for c in value) and "\\" not in value and parsed.port != 0
    except (ValueError, UnicodeError):
        return False


def _oauth(row, add):
    def cue(key, title, fix, severity="WARNING"):
        add(row["id"], "oauth", key, title, fix, severity)
    if not all(_https(row[k]) for k in ("issuer", "authorization_endpoint", "token_endpoint")):
        cue("endpoint-transport", "Declared web-client endpoints need transport review", "Use valid HTTPS endpoints without embedded credentials or fragments; verify provider metadata independently.")
    if not all(_https(uri) for uri in row["redirect_uris"]):
        cue("redirect-transport", "Declared redirect URIs differ from this HTTPS web-client policy", "Review exact HTTPS callbacks; native/loopback and custom-scheme exceptions need a separate assessment.", "INFO")
    if row["redirect_matching"] != "exact" or any("*" in uri or "%2a" in uri.lower() for uri in row["redirect_uris"]):
        cue("redirect-matching", "Declared redirect matching allows broader destinations", "Enforce exact registered redirect URI matching and review approved exceptions.")
    code = "authorization_code" in row["grant_types"] or any("code" in t.split() for t in row["response_types"])
    if code and (not row["pkce_required"] or "S256" not in row["pkce_methods"]):
        cue("pkce-policy", "Declared code flow lacks required S256 PKCE policy", "Require PKCE with S256 and verify challenge/verifier binding on the server.")
    if code and "plain" in row["pkce_methods"]:
        cue("pkce-plain", "Declared code flow permits plain PKCE", "Require a challenge method that protects verifier disclosure, normally S256.")
    if "implicit" in row["grant_types"] or any("token" in t.split() for t in row["response_types"]):
        cue("front-channel-token", "Declared flow permits front-channel access-token issuance", "Prefer authorization code flow with PKCE and review token leakage defenses.")
    if "password" in row["grant_types"]:
        cue("password-grant", "Declared web client permits password grant", "Remove resource-owner password grant from the client flow.")
    if (row["response_types"] or code or "implicit" in row["grant_types"]) and not row["state_required"]:
        cue("csrf-binding", "Declared flow does not require state binding", "Independently verify CSRF/session binding; correctly deployed PKCE or nonce may provide alternative protection.", "INFO")
    if row["oidc"] and not row["nonce_required"]:
        cue("nonce-binding", "Declared OIDC flow does not require nonce binding", "Review replay/session binding and ID-token validation for the chosen flow; absence alone is not proof of exploitation.", "INFO")
    if row["client_type"] == "public" and "client_credentials" in row["grant_types"]:
        cue("public-client-credentials", "Public-client declaration includes client credentials grant", "Use confidential client authentication for this grant and separate public-client flows.")


def review_evidence(data, *, now=None):
    validate_evidence(data)
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    if type(now) not in (int, float) or not 0 <= now <= 253402300799 or not math.isfinite(now):
        raise ValueError("Invalid review clock")
    findings, observations = [], []

    def add(case, skill, key, title, fix, severity):
        findings.append({"rule_id": "identity." + skill + "." + key, "skill": "offensive-" + skill,
            "test_case": case, "title": title, "severity": severity, "cwe": "CWE-287",
            "message": title + ". " + fix, "remediation": fix, "code": "",
            "file_path": "external-evidence", "line_start": 1, "line_end": 1,
            "engine": "auth-identity-review", "verification_status": "unverified"})

    for row in data["jwt_samples"]:
        fmt = _jwt(row, now, add)
        observations.append({"case": row["id"], "skill": "offensive-jwt", "format": fmt, "signature_verification": "not-performed"})
    for row in data["oauth_clients"]:
        _oauth(row, add)
        observations.append({"case": row["id"], "skill": "offensive-oauth", "configuration_verified_against_provider": False})
    return {"engine": "auth-identity-review", "schema_version": 1, "category": "Auth & Identity",
        "reviewed_at": datetime.fromtimestamp(now, timezone.utc).isoformat(), "references": REFERENCES,
        "skills": [{**s, "cases_reviewed": sum(o["skill"] == s["id"] for o in observations),
            "status": "partial-offline-review" if any(o["skill"] == s["id"] for o in observations) else "not-assessed"} for s in catalog()],
        "observations": observations, "findings": findings, "network_requests": 0,
        "all_skills_automated": False, "real_world_effectiveness": "unverified",
        "limitations": ["JWT headers and claims are untrusted; cryptographic signatures, server acceptance and authentication are not verified",
            "No token signing, mutation, replay, cracking, key retrieval, OIDC discovery or provider requests",
            "Only supplied compact JWS samples and declared web-client settings; JWE and other serializations unsupported",
            "OAuth configuration declarations are not evidence that provider/session controls are enforced",
            "No claim values, URLs, tokens, key material or client secrets are included in this report",
            "Absence of cues does not establish secure authentication; end-to-end SSO, key confusion, session and scope tests remain manual"]}


def review_file(path, *, authorized=False):
    if not authorized:
        raise PermissionError("Identity evidence review requires explicit authorization")
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    report = review_evidence(_json(raw))
    report["input_sha256"] = hashlib.sha256(raw).hexdigest()
    return report
