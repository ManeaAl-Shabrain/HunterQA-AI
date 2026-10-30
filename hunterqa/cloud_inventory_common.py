"""Provider-neutral private input and bounded JSON checks; no network or SDK discovery."""
from __future__ import annotations

import math
import re

from .bounty import _decode_json
from .engagement import _expiry, utcnow


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
