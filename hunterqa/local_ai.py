"""Bounded Ollama transport: fixed loopback, no proxies or redirects."""
from __future__ import annotations

import json
import urllib.request

GENERATE_URL = "http://127.0.0.1:11434/api/generate"
MAX_REQUEST_BYTES = 1_000_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def generate(payload: dict, *, endpoint=GENERATE_URL, timeout=120, max_response=512_000) -> dict:
    """Send data only to the exact local generate endpoint; never execute output."""
    if endpoint != GENERATE_URL:
        raise ValueError("AI generation requires the fixed loopback Ollama endpoint")
    if type(max_response) is not int or not 1 <= max_response <= 1_000_000:
        raise ValueError("Invalid model response limit")
    if type(timeout) not in (int, float) or not 0 < timeout <= 240:
        raise ValueError("Invalid model timeout")
    body = json.dumps(payload, allow_nan=False).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        raise ValueError("Model request exceeds size limit")
    request = urllib.request.Request(endpoint, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        if response.geturl() != GENERATE_URL:
            raise ValueError("Unexpected model destination")
        raw = response.read(max_response + 1)
    if len(raw) > max_response:
        raise ValueError("Model response exceeds size limit")
    result = json.loads(raw.decode("utf-8"))
    if not isinstance(result, dict):
        raise ValueError("Invalid model response object")
    return result
