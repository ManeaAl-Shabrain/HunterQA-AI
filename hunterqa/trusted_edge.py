"""Authenticated single-hop TLS edge admission, before Flask sees proxy data."""
import hmac
import ipaddress
import re
from urllib.parse import urlsplit


def public_origin(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048 or any(not 33 <= ord(c) < 127 for c in value):
        raise ValueError("Invalid explicit HTTPS workspace origin")
    parts = urlsplit(value)
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None or parts.password is not None
            or parts.path not in ("", "/") or parts.query or parts.fragment or parts.port not in (None, 443)
            or any(c in value for c in ("\\", "%", "'", '"', ";"))):
        raise ValueError("Workspace edge requires an exact HTTPS origin on port 443")
    host = parts.hostname.lower()
    if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
        raise ValueError("Use a canonical DNS hostname for the TLS edge")
    return "https://" + host


class TrustedEdge:
    def __init__(self, application, origin, secret):
        self.application, self.authority, self.secret = application, urlsplit(public_origin(origin)).netloc, secret

    def __call__(self, environ, start_response):
        try:
            peer = ipaddress.ip_address(environ.get("REMOTE_ADDR", ""))
            client = environ.get("HTTP_X_FORWARDED_FOR", "")
            ip = ipaddress.ip_address(client)
            token = environ.get("HTTP_X_HUNTERQA_EDGE_KEY", "")
            valid = (peer.is_loopback and not ip.is_unspecified and not ip.is_multicast and str(ip) == client and environ.get("HTTP_HOST", "").lower() == self.authority
                and environ.get("HTTP_X_FORWARDED_PROTO") == "https" and isinstance(token, str)
                and len(token) == 64 and token.isascii() and hmac.compare_digest(token, self.secret))
        except ValueError:
            valid = False
        if not valid:
            start_response("403 Forbidden", [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")])
            return [b"Workspace gateway admission required"]
        environ["REMOTE_ADDR"] = client
        environ["wsgi.url_scheme"] = "https"
        environ["HTTP_HOST"] = self.authority
        environ["hunterqa.edge_verified"] = True
        for name in list(environ):
            if name.startswith("HTTP_X_FORWARDED_") or name in ("HTTP_FORWARDED", "HTTP_X_HUNTERQA_EDGE_KEY"):
                environ.pop(name)
        return self.application(environ, start_response)
