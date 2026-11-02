"""One scope-admitted, verified TLS handshake; no HTTP or insecure fallback."""
from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import time

from .bounty import _approved_file, resolve_pinned
from .engagement import _policy_snapshot, digest, utcnow
from .source_files import read_bounded
from . import shared_quota


def inspect_service(profile, target, *, authorized=False, ca_file=None):
    """Inspect one explicitly authorized TLS endpoint using platform trust or a saved CA."""
    if authorized is not True:
        raise PermissionError("TLS inspection requires --authorized and written endpoint permission")
    policy, profile_hash = _policy_snapshot(profile)
    parts, host, port, _ = policy.authorize_url(target, "HEAD" if "HEAD" in policy.methods else "GET")
    # A handshake is host/port-wide, not a path-specific application assessment.
    if parts.scheme != "https" or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("TLS inspection requires an exact HTTPS host/port root URL")
    policy.authorize_url(f"https://{host}:{port}/", "HEAD" if "HEAD" in policy.methods else "GET")
    ca_hash = None
    # PROTOCOL_TLS_CLIENT requires certificates and hostname matching. Construct
    # explicitly so SSLKEYLOGFILE cannot silently export session secrets.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
    if ca_file is None:
        context.load_default_certs()
    else:
        raw = read_bounded(_approved_file(ca_file), 262144)
        try:
            pem = raw.decode("ascii")
            if "PRIVATE KEY" in pem or "-----BEGIN CERTIFICATE-----" not in pem:
                raise ValueError
            context.load_verify_locations(cadata=pem)
        except (ValueError, UnicodeError, ssl.SSLError):
            raise ValueError("Invalid saved public CA certificate bundle; contents withheld") from None
        ca_hash = hashlib.sha256(raw).hexdigest()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["h2", "http/1.1"])
    report = {"engine": "scoped-tls-inspection", "schema_version": 1,
        "observed_at": utcnow().isoformat(), "policy_sha256": profile_hash,
        "target_sha256": digest(target), "port": port,
        "trust_source": "platform-default" if ca_file is None else "owner-supplied-ca",
        "ca_bundle_sha256": ca_hash, "openssl_version": ssl.OPENSSL_VERSION,
        "connection_attempts": 0, "http_requests": 0, "outcome": "inconclusive",
        "certificate_and_hostname_verified": None, "certificate_verification_code": None,
        "tls_version": None, "cipher": None, "alpn": None, "leaf_certificate_sha256": None,
        "revocation_verified": False, "service_product_verified": False,
        "os_fingerprint_verified": False, "findings": [],
        "limitations": [
            "One TLS 1.2+ handshake; no application request, retries, redirect, proxy, client certificate or insecure fallback",
            "A rejected certificate is a client trust/name/time/policy failure, not proof of an exploitable vulnerability",
            "No cipher/protocol enumeration, OCSP/CRL retrieval, service/version identification, UDP, AD or attack-path testing",
            "Platform trust and OpenSSL policy vary; a supplied CA replaces platform roots and its ownership is unverified",
            "Five-second combined TCP/handshake budget after DNS; OS DNS resolution has no portable deadline",
            "Invocation-local scope and optional cooperating host-local quota; no distributed quota, persistent approval or independent owner verification"]}
    with shared_quota.invocation(1) as admission:
        report["shared_quota"] = admission.receipt
        admission.ensure_active()
        ip = resolve_pinned(policy, host, port)
        admission.ensure_active()
        family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
        deadline = time.monotonic() + 5
        try:
            with socket.socket(family, socket.SOCK_STREAM) as raw_socket:
                raw_socket.settimeout(5)
                admission.ensure_active()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                raw_socket.settimeout(remaining)
                report["connection_attempts"] = 1
                raw_socket.connect((ip, port))
                admission.ensure_active()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                raw_socket.settimeout(remaining)
                with context.wrap_socket(raw_socket, server_hostname=host) as tls:
                    certificate = tls.getpeercert(binary_form=True)
                    cipher = tls.cipher()
                    report.update(outcome="verified", certificate_and_hostname_verified=True,
                        tls_version=tls.version(), cipher={"name": cipher[0], "bits": cipher[2]},
                        alpn=tls.selected_alpn_protocol(),
                        leaf_certificate_sha256=hashlib.sha256(certificate).hexdigest())
        except shared_quota.QuotaStopped:
            report["outcome"] = "quota-stopped"
        except ssl.SSLCertVerificationError as exc:
            report.update(outcome="certificate-rejected", certificate_and_hostname_verified=False,
                          certificate_verification_code=exc.verify_code)
        except TimeoutError:
            report["outcome"] = "timeout"
        except ConnectionRefusedError:
            report["outcome"] = "refused"
        except ssl.SSLError:
            report["outcome"] = "tls-error"
        except OSError:
            report["outcome"] = "unreachable"
    return report
