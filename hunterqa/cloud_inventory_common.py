"""Provider-neutral private input and bounded JSON checks; no network or SDK discovery."""
from __future__ import annotations

import math
import hashlib
import json
import re

from .bounty import _decode_json
from .engagement import _expiry, utcnow


def read_credentials(path, provider=None):
    """Reuse legacy private files or a purpose-bound in-memory credential source."""
    if provider is None:
        from .bounty import _approved_file
        from .source_files import read_bounded
        raw = read_bounded(_approved_file(path), 32768)
        return raw, hashlib.sha256(raw).hexdigest()
    if path is not None:
        raise ValueError("Choose either a private credential file or an encrypted source")
    raw, binding = provider()
    if not isinstance(raw, bytes) or len(raw) > 32768 or not isinstance(binding, str) or not re.fullmatch(r"[a-f0-9]{64}", binding):
        raise ValueError("Invalid bounded credential source")
    return raw, binding


def token_provider(provider, session_file, session_key):
    """Decrypt only into memory; never materialize bearer credentials on disk."""
    from .assessment_sessions import load_document
    hosts = {"azure": {"azure-arm": "https://management.azure.com"}, "gcp": {
        "gcp-context": "https://cloudresourcemanager.googleapis.com", "gcp-assets": "https://cloudasset.googleapis.com"}}
    if provider not in hosts:
        raise ValueError("Unsupported token vault provider")
    def read():
        document, binding = load_document(session_file, session_key, purpose=provider + "-token")
        actors = document["actors"]
        if set(actors) != set(hosts[provider]):
            raise ValueError("Dedicated provider-origin token actors required")
        token = None
        for name, origin in hosts[provider].items():
            actor = actors[name]
            if actor["origin"] != origin or set(actor["headers"]) != {"Authorization"} or actor["cookies"] or actor["local_storage"]:
                raise ValueError("Token vault origin differs from the fixed provider API")
            value = actor["headers"]["Authorization"]
            if token is not None and token != value:
                raise ValueError("Provider origins must use the same reviewed identity token")
            token = value
        payload = {"access_token": token, "expires_at": document["expires_at"]}
        raw = json.dumps(payload, sort_keys=True).encode()
        temporary_credentials(raw)
        return raw, binding
    return read


def live_window(expiry):
    if not 0 < (_expiry(expiry) - utcnow()).total_seconds() <= 86400:
        raise ValueError("Expired or invalid cloud authorization window")


def temporary_credentials(raw):
    try:
        data = _decode_json(raw)
        if not isinstance(data, dict) or set(data) != {"access_token", "expires_at"}:
            raise ValueError
        token = data["access_token"]
        if not isinstance(token, str) or not 16 <= len(token) <= 16384 or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token):
            raise ValueError
        live_window(data["expires_at"])
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("Invalid temporary cloud credential file; contents withheld") from None
    return data


def bounded_json(raw):
    if not isinstance(raw, bytes) or len(raw) > 1048576:
        raise ValueError("Cloud response size rejected")
    data = _decode_json(raw)
    stack, count = [(data, 0)], 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > 20000 or depth > 32 or (isinstance(value, float) and not math.isfinite(value)):
            raise ValueError("Cloud response structure rejected")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
    if not isinstance(data, dict):
        raise ValueError("Cloud response shape rejected")
    return data
