"""Offline RS256 ID-token verification against explicit owner-supplied anchors."""
import hashlib
import hmac
from importlib.metadata import PackageNotFoundError, version
import re
import time
from urllib.parse import parse_qsl, urlsplit

from packaging.version import Version

from .bounty import _approved_file
from .engagement import digest
from .identity_review import _json, _segment
from .source_files import read_bounded

SAFE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


def _text(value, limit=256):
    return (isinstance(value, str) and 0 < len(value) <= limit
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def validate_policy(policy):
    fields = {"schema_version", "issuer", "client_id", "expected_nonce", "max_lifetime_seconds",
              "max_age_seconds", "expected_subject", "expected_tenant", "allow_loopback_issuer"}
    if (not isinstance(policy, dict) or set(policy) != fields or type(policy["schema_version"]) is not int
            or policy["schema_version"] != 1 or type(policy["allow_loopback_issuer"]) is not bool
            or not _text(policy["issuer"], 2048) or not _text(policy["client_id"])
            or not isinstance(policy["expected_nonce"], str)
            or re.fullmatch(r"[A-Za-z0-9_-]{16,128}", policy["expected_nonce"]) is None
            or any(value is not None and not _text(value) for value in
                   (policy["expected_subject"], policy["expected_tenant"]))):
        raise ValueError("Invalid explicit ID-token policy; private contents withheld")
    for key, lower, upper in (("max_lifetime_seconds", 1, 86400), ("max_age_seconds", 1, 3600)):
        if type(policy[key]) is not int or not lower <= policy[key] <= upper:
            raise ValueError("Invalid ID-token time policy")
    try:
        parts = urlsplit(policy["issuer"])
        port = parts.port
    except ValueError:
        raise ValueError("Invalid exact issuer URI") from None
    if (not parts.hostname or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or "\\" in policy["issuer"]
            or parts.scheme not in {"https", "http"}):
        raise ValueError("Invalid exact issuer URI")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid issuer port")
    if parts.scheme != "https" and not (policy["allow_loopback_issuer"] and parts.hostname == "127.0.0.1" and port):
        raise ValueError("Plaintext issuer is restricted to an explicit 127.0.0.1 fixture")


def _engine():
    try:
        import jwt
        if Version(version("PyJWT")) < Version("2.15.1") or Version(version("cryptography")) < Version("50.0.2"):
            raise RuntimeError("Upgrade the identity extra before verifying tokens")
        return jwt
    except (ImportError, PackageNotFoundError):
        raise RuntimeError("Install the optional identity extra before verifying tokens") from None


def _keys(jwks, jwt):
    if not isinstance(jwks, dict) or set(jwks) != {"keys"} or not isinstance(jwks["keys"], list) or not 1 <= len(jwks["keys"]) <= 10:
        raise ValueError("Expected 1..10 explicit RSA public keys")
    keys = {}
    for row in jwks["keys"]:
        if (not isinstance(row, dict) or not {"kty", "kid", "n", "e"} <= set(row)
                or not set(row) <= {"kty", "kid", "n", "e", "alg", "use", "key_ops"}
                or row["kty"] != "RSA" or not isinstance(row["kid"], str) or not SAFE_ID.fullmatch(row["kid"])
                or row["kid"] in keys or row.get("alg", "RS256") != "RS256"
                or row.get("use", "sig") != "sig" or row.get("key_ops", ["verify"]) != ["verify"]
                or not isinstance(row["n"], str) or not 300 <= len(row["n"]) <= 800 or row["e"] != "AQAB"):
            raise ValueError("Invalid, ambiguous or unsupported public signing key")
        modulus = _segment(row["n"])
        if not 256 <= len(modulus) <= 512 or modulus[0] == 0:
            raise ValueError("Unsupported RSA modulus")
        try:
            public = jwt.PyJWK.from_dict(row, algorithm="RS256").key
            if not 2048 <= public.key_size <= 4096 or public.public_numbers().e != 65537:
                raise ValueError("Unsupported RSA key size or exponent")
        except (jwt.PyJWTError, TypeError, KeyError, ValueError):
            raise ValueError("Invalid RSA public key") from None
        keys[row["kid"]] = public
    return keys


def verify_id_token(token, jwks, policy):
    validate_policy(policy)
    jwt = _engine()
    keys = _keys(jwks, jwt)
    if not isinstance(token, str) or not 1 <= len(token) <= 16384 or not token.isascii():
        raise ValueError("Expected a bounded compact ID token")
    result = {"engine": "hunterqa_signed_id_token_verification", "schema_version": 1,
        "token_sha256": hashlib.sha256(token.encode()).hexdigest(), "jwks_sha256": digest(jwks),
        "policy_sha256": digest(policy), "accepted": False, "signature_and_policy_verified": False,
        "key_anchor_trust": "owner_supplied_unverified", "server_acceptance_verified": False,
        "tenant_isolation_verified": False, "network_requests": 0, "review_required": True}
    try:
        segments = token.split(".")
        if len(segments) != 3:
            raise ValueError("Unsupported token format")
        header, claims = (_json(_segment(part)) for part in segments[:2])
        _segment(segments[2])
        if (not isinstance(header, dict) or header.get("alg") != "RS256" or header.get("typ", "JWT") != "JWT"
                or not isinstance(header.get("kid"), str) or header["kid"] not in keys
                or set(header) & {"crit", "b64", "jku", "x5u", "x5c", "zip"}
                or not isinstance(claims, dict)):
            raise ValueError("Unsupported or untrusted token header")
        for key in ("exp", "iat"):
            if type(claims.get(key)) is not int or claims[key] < 0:
                raise ValueError("Strict NumericDate required")
        for key in ("nbf", "auth_time"):
            if key in claims and (type(claims[key]) is not int or claims[key] < 0):
                raise ValueError("Strict NumericDate required")
        if not _text(claims.get("sub")) or not _text(claims.get("nonce"), 128):
            raise ValueError("Missing bounded subject or nonce")
        audience = claims.get("aud")
        if isinstance(audience, str):
            audiences = [audience]
        elif isinstance(audience, list):
            audiences = audience
        else:
            raise ValueError("Invalid audience")
        if (not 1 <= len(audiences) <= 10 or any(not _text(v) for v in audiences)
                or len(set(audiences)) != len(audiences) or policy["client_id"] not in audiences
                or (len(audiences) > 1 and claims.get("azp") != policy["client_id"])
                or ("azp" in claims and claims["azp"] != policy["client_id"])):
            raise ValueError("Audience or authorized party differs")
        verified = jwt.decode(token, keys[header["kid"]], algorithms=["RS256"],
            issuer=policy["issuer"], audience=policy["client_id"], leeway=0,
            options={"require": ["iss", "sub", "aud", "iat", "exp", "nonce"]})
        now = int(time.time())
        if (verified != claims or claims.get("iss") != policy["issuer"]
                or not isinstance(claims["nonce"], str) or not claims["nonce"].isascii()
                or not hmac.compare_digest(claims["nonce"], policy["expected_nonce"])
                or not 0 < claims["exp"] - claims["iat"] <= policy["max_lifetime_seconds"]
                or not 0 <= now - claims["iat"] <= policy["max_age_seconds"]
                or ("auth_time" in claims and claims["auth_time"] > claims["iat"])
                or (policy["expected_subject"] is not None and claims["sub"] != policy["expected_subject"])
                or (policy["expected_tenant"] is not None and claims.get("tenant_id") != policy["expected_tenant"])):
            raise ValueError("ID-token policy mismatch")
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, OverflowError):
        result["reason"] = "signature_claims_or_supported_format_rejected"
        return result
    return {**result, "accepted": True, "signature_and_policy_verified": True,
            "reason": "supported_signature_and_claim_policy_matched",
            "subject_binding_checked": policy["expected_subject"] is not None,
            "tenant_claim_binding_checked": policy["expected_tenant"] is not None,
            "access_token_binding_verified": False}


def verify_file(path):
    data = _json(read_bounded(_approved_file(path), 262144))
    if (not isinstance(data, dict) or set(data) != {"schema_version", "token", "jwks", "policy"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1):
        raise ValueError("Invalid signed ID-token input envelope")
    return verify_id_token(data["token"], data["jwks"], data["policy"])


def pkce_challenge(verifier):
    import base64
    if not isinstance(verifier, str) or re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier) is None:
        raise ValueError("Invalid bounded PKCE verifier")
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")


def validate_callback(location, callback, state):
    """Parse only; never follow a callback or URL supplied by a token."""
    if (not _text(location, 2048) or not _text(callback, 2048) or not isinstance(state, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{16,128}", state) is None):
        raise ValueError("Invalid authorization response")
    try:
        registered = urlsplit(callback)
        parts = urlsplit(location)
        port = registered.port
    except ValueError:
        raise ValueError("Invalid registered callback URI") from None
    if (not registered.hostname or registered.username is not None or registered.password is not None
            or registered.query or registered.fragment or "\\" in callback or
            not (registered.scheme == "https" or
                 (registered.scheme == "http" and registered.hostname == "127.0.0.1" and port))):
        raise ValueError("Unsupported registered callback URI")
    if parts.fragment or parts._replace(query="").geturl() != callback:
        raise ValueError("Callback differs from the exact registered URI")
    pairs = parse_qsl(parts.query, strict_parsing=True, keep_blank_values=True, max_num_fields=2)
    values = dict(pairs)
    if (len(pairs) != 2 or set(values) != {"code", "state"}
            or not SAFE_ID.fullmatch(values["code"]) or not SAFE_ID.fullmatch(values["state"])
            or not hmac.compare_digest(values["state"], state)):
        raise ValueError("Authorization state or code rejected")
    return values["code"]
