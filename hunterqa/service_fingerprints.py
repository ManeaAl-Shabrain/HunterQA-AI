"""Exact-endpoint bounded protocol/product claims; no authentication or exploit."""
import hashlib
import ipaddress
import socket
import time

from . import shared_quota
from .bounty import _approved_file, _decode_json
from .engagement import _expiry, digest, utcnow
from .source_files import read_bounded
from .ssh_inspection import FIELDS, validate_contract as validate_endpoint

PROTOCOLS = {"ssh", "smtp", "ftp", "redis", "http"}


def validate(data):
    if not isinstance(data, dict) or set(data) != FIELDS - {"transport"} | {"protocol"} or data["protocol"] not in PROTOCOLS:
        raise ValueError("Choose one supported protocol and an exact endpoint contract")
    validate_endpoint({key: value for key, value in data.items() if key != "protocol"} | {"transport": "tcp-ssh-identification"})
    return data


def interpret(protocol, raw):
    valid = {"ssh": raw.startswith((b"SSH-2.0-", b"SSH-1.99-")), "smtp": raw.startswith(b"220 ") or raw.startswith(b"220-"),
        "ftp": raw.startswith(b"220 ") or raw.startswith(b"220-"), "redis": raw.startswith(b"+PONG\r\n"),
        "http": raw.startswith((b"HTTP/1.0 ", b"HTTP/1.1 "))}[protocol]
    products = ((b"OpenSSH", "OpenSSH"), (b"dropbear", "Dropbear"), (b"Postfix", "Postfix"),
        (b"Exim", "Exim"), (b"vsFTPd", "vsftpd"), (b"ProFTPD", "ProFTPD"), (b"nginx", "nginx"),
        (b"Apache", "Apache"), (b"Microsoft-IIS", "IIS"))
    hint = next((label for marker, label in products if marker.lower() in raw.lower()), None) if valid else None
    return {"protocol_response_observed": valid, "advertised_product_hint": hint,
        "advertised_os_hint": next((name for name in ("Ubuntu", "Debian", "Windows", "FreeBSD") if name.encode().lower() in raw.lower()), None) if valid else None,
        "response_sha256": hashlib.sha256(raw).hexdigest(), "response_bytes": len(raw),
        "product_verified": False, "os_verified": False, "vulnerability_verified": False}


def inspect(input_file, *, authorized=False):
    if authorized is not True:
        raise PermissionError("Service identification requires --authorized")
    path = _approved_file(input_file)
    raw_contract = read_bounded(path, 16384)
    contract = validate(_decode_json(raw_contract))
    report = {"engine": "scoped-service-fingerprint", "schema_version": 1,
        "input_sha256": hashlib.sha256(raw_contract).hexdigest(), "endpoint_sha256": digest([contract["server_ip"], contract["server_port"]]),
        "protocol": contract["protocol"], "connection_attempts": 0, "application_bytes_sent": 0,
        "outcome": "inconclusive", "review_required": True, "limitations": [
            "One numeric TCP endpoint; five seconds and 4096 response bytes maximum; no DNS, retry, login, credentials or exploit",
            "Banner/product/OS strings are spoofable server claims; SMTP/FTP 220 greetings alone do not distinguish the protocols",
            "This does not enumerate OS internals, service vulnerabilities or authenticated AD access"]}
    with shared_quota.invocation(1) as admission:
        report["shared_quota"] = admission.receipt
        deadline = time.monotonic() + min(5, (_expiry(contract["expires_at"]) - utcnow()).total_seconds())

        def gate(channel):
            admission.ensure_active()
            if read_bounded(_approved_file(path), 16384) != raw_contract:
                raise PermissionError("Endpoint contract changed")
            validate(contract)
            remaining = min(deadline - time.monotonic(), (_expiry(contract["expires_at"]) - utcnow()).total_seconds())
            if remaining <= 0:
                raise TimeoutError
            channel.settimeout(remaining)

        address = ipaddress.ip_address(contract["server_ip"])
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        data = b""
        try:
            with socket.socket(family, socket.SOCK_STREAM) as channel:
                gate(channel)
                report["connection_attempts"] = 1
                channel.connect((str(address), contract["server_port"]))
                wire = b"PING\r\n" if contract["protocol"] == "redis" else b""
                if contract["protocol"] == "http":
                    host = "[" + str(address) + "]" if address.version == 6 else str(address)
                    wire = ("HEAD / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n").encode()
                if wire:
                    gate(channel)
                    channel.sendall(wire)
                    report["application_bytes_sent"] = len(wire)
                while len(data) < 4096:
                    gate(channel)
                    chunk = channel.recv(min(512, 4096 - len(data)))
                    if not chunk:
                        break
                    data += chunk
                    if (contract["protocol"] == "http" and b"\r\n\r\n" in data) or (contract["protocol"] != "http" and b"\r\n" in data):
                        break
                report.update(interpret(contract["protocol"], data))
                report["outcome"] = "observed" if report["protocol_response_observed"] else "unrecognized-response"
        except (OSError, ValueError, PermissionError) as error:
            report["outcome"] = "inconclusive"
            report["error_type"] = type(error).__name__
    return report
