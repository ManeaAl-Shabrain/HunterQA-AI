"""Bounded server-first SSH identification observation, without a client exchange."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import time
from datetime import timedelta

from . import shared_quota
from .bounty import _approved_file, _decode_json
from .engagement import _expiry, digest, utcnow
from .source_files import read_bounded

FIELDS = {"schema_version", "transport", "authorization_reference", "acknowledged_authorization",
          "expires_at", "server_ip", "server_port", "allow_private_network"}
IDENTIFICATION = re.compile(rb"SSH-([!-~]+?)-([!-~]+?)(?: ([ -~]*))?\r\n\Z")


def validate_contract(data):
    def reject():
        raise ValueError("Invalid or expired exact SSH endpoint contract; private values withheld") from None
    if not isinstance(data, dict) or set(data) != FIELDS:
        reject()
    if type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["transport"] != "tcp-ssh-identification":
        reject()
    reference = data["authorization_reference"]
    if (data["acknowledged_authorization"] is not True or not isinstance(reference, str)
            or not 1 <= len(reference) <= 200 or not reference.strip() or any(ord(c) < 32 for c in reference)):
        reject()
    try:
        remaining = _expiry(data["expires_at"]) - utcnow()
        address = ipaddress.ip_address(data["server_ip"])
    except (TypeError, ValueError):
        reject()
    if (not timedelta(0) < remaining <= timedelta(hours=24)
            or not isinstance(data["server_ip"], str) or str(address) != data["server_ip"] or "%" in data["server_ip"]
            or type(data["allow_private_network"]) is not bool
            or address.is_unspecified or address.is_multicast or address.is_link_local
            or (address.is_reserved and not address.is_loopback)
            or (not address.is_global and not data["allow_private_network"])):
        reject()
    if type(data["server_port"]) is not int or not 1 <= data["server_port"] <= 65535:
        reject()
    return data


def _interpret(line):
    """Strict CRLF/ASCII subset of RFC 4253 section 4.2; never publish raw data."""
    match = IDENTIFICATION.fullmatch(line)
    if len(line) > 255 or match is None:
        return {"outcome": "invalid-identification"}
    protocol, software, _ = match.groups()
    if b"-" in protocol or b"-" in software:
        return {"outcome": "invalid-identification"}
    # Unsupported, arbitrary protocol strings are not copied into reports.
    if protocol not in (b"2.0", b"1.99", b"1.5", b"1.3"):
        return {"outcome": "unsupported-protocol", "identification_sha256": hashlib.sha256(line).hexdigest()}
    product = next((label for prefix, label in ((b"OpenSSH_", "OpenSSH"),
        (b"dropbear_", "Dropbear"), (b"libssh_", "libssh")) if software.startswith(prefix)), None)
    return {"outcome": "identification-observed", "advertised_protocol": protocol.decode("ascii"),
        "advertised_product_hint": product, "software_sha256": hashlib.sha256(software).hexdigest(),
        "identification_sha256": hashlib.sha256(line).hexdigest()}


def inspect_ssh(input_file, *, authorized=False):
    if authorized is not True:
        raise PermissionError("SSH identification requires --authorized and written endpoint permission")
    path = _approved_file(input_file)
    raw = read_bounded(path, 16384)
    try:
        contract = validate_contract(_decode_json(raw))
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise ValueError("Invalid exact SSH endpoint contract; private values withheld") from None
    report = {"engine": "scoped-ssh-identification", "schema_version": 1,
        "observed_at": utcnow().isoformat(), "input_sha256": hashlib.sha256(raw).hexdigest(),
        "server_sha256": digest([contract["server_ip"], contract["server_port"]]),
        "server_port": contract["server_port"], "connection_attempts": 0, "application_bytes_sent": 0,
        "received_bytes": 0, "pre_identification_lines": 0, "outcome": "inconclusive",
        "advertised_protocol": None, "advertised_product_hint": None,
        "software_sha256": None, "identification_sha256": None,
        "server_identity_verified": False, "service_product_verified": False,
        "vulnerability_verified": False, "findings": [], "limitations": [
            "One numeric TCP endpoint; server-first observation only, no client identification, key exchange, authentication or application data",
            "At most 2048 received bytes, ten pre-identification lines and 255 bytes per line; strict CRLF printable-ASCII identification subset",
            "Five-second combined TCP/read deadline capped by contract expiry; no DNS, proxy, retry, forwarding, host-key or algorithm enumeration",
            "Protocol and product hints are unauthenticated server claims; no verified version, CVE, OS fingerprint or vulnerability inference",
            "Optional cooperating host-local quota; trusted local operator attestation, not verified owner consent, tenant isolation or cross-host enforcement",
            "Hashes do not authenticate evidence or anonymize guessable endpoint/software values; no representative field effectiveness claim"]}
    with shared_quota.invocation(1) as admission:
        report["shared_quota"] = admission.receipt
        deadline = time.monotonic() + min(5.0, (_expiry(contract["expires_at"]) - utcnow()).total_seconds())

        def gate(channel):
            admission.ensure_active()
            try:
                current = read_bounded(_approved_file(path), 16384)
            except OSError:
                raise PermissionError("SSH endpoint contract unavailable; private values withheld") from None
            if current != raw:
                raise PermissionError("SSH endpoint contract changed; private values withheld")
            validate_contract(contract)
            remaining = min(deadline - time.monotonic(), (_expiry(contract["expires_at"]) - utcnow()).total_seconds())
            if remaining <= 0:
                raise TimeoutError
            channel.settimeout(remaining)

        family = socket.AF_INET6 if ipaddress.ip_address(contract["server_ip"]).version == 6 else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as channel:
                gate(channel)
                report["connection_attempts"] = 1
                channel.connect((contract["server_ip"], contract["server_port"]))
                pending = b""
                while report["received_bytes"] < 2048:
                    gate(channel)
                    chunk = channel.recv(min(256, 2048 - report["received_bytes"]))
                    if not chunk:
                        report["outcome"] = "closed-before-identification"
                        break
                    report["received_bytes"] += len(chunk)
                    pending += chunk
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        line += b"\n"
                        if len(line) > 255 or not line.endswith(b"\r\n"):
                            report["outcome"] = "invalid-identification"
                            return report
                        if line.startswith(b"SSH-"):
                            report.update(_interpret(line))
                            return report
                        report["pre_identification_lines"] += 1
                        if report["pre_identification_lines"] > 10:
                            report["outcome"] = "pre-identification-limit"
                            return report
                    if len(pending) >= 255:
                        report["outcome"] = "line-limit"
                        break
                else:
                    report["outcome"] = "byte-limit"
        except shared_quota.QuotaStopped:
            report["outcome"] = "quota-stopped"
        except (PermissionError, ValueError):
            report["outcome"] = "contract-stopped"
        except TimeoutError:
            report["outcome"] = "timeout"
        except ConnectionRefusedError:
            report["outcome"] = "refused"
        except OSError:
            report["outcome"] = "unreachable"
    return report
