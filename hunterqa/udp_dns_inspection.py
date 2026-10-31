"""One nonrecursive UDP DNS A question under an expiring exact-endpoint contract."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import time
from datetime import timedelta
from importlib.metadata import PackageNotFoundError, version

from packaging.version import InvalidVersion, Version

from .bounty import _approved_file, _decode_json
from .engagement import _expiry, digest, utcnow
from .source_files import read_bounded
from . import shared_quota

FIELDS = {"schema_version", "transport", "authorization_reference", "acknowledged_authorization",
          "expires_at", "server_ip", "server_port", "query_name", "expected_ipv4", "allow_private_network"}
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _engine():
    try:
        if Version(version("dnspython")) < Version("2.9.1"):
            raise ImportError
        import dns.message
        import dns.flags
        import dns.rcode
        import dns.rdatatype
        import dns.rdataclass
        import dns.exception
    except (PackageNotFoundError, ImportError, InvalidVersion):
        raise RuntimeError("Install .[network] for bounded UDP DNS inspection (dnspython>=2.9.1)") from None
    return dns


def validate_contract(data, *, now=None):
    def reject():
        raise ValueError("Invalid or expired exact UDP DNS contract; private values withheld") from None
    if not isinstance(data, dict) or set(data) != FIELDS:
        reject()
    if type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["transport"] != "udp-dns":
        reject()
    reference = data["authorization_reference"]
    if (data["acknowledged_authorization"] is not True or not isinstance(reference, str)
            or not 1 <= len(reference) <= 200 or not reference.strip() or any(ord(c) < 32 for c in reference)):
        reject()
    try:
        remaining = _expiry(data["expires_at"]) - (now or utcnow())
        if not timedelta(0) < remaining <= timedelta(hours=24):
            reject()
        address = ipaddress.ip_address(data["server_ip"])
        expected = data["expected_ipv4"]
        if not isinstance(expected, list) or not 1 <= len(expected) <= 8:
            reject()
        if any(not isinstance(a, str) or str(ipaddress.IPv4Address(a)) != a for a in expected) or len(set(expected)) != len(expected):
            reject()
    except (ValueError, TypeError):
        reject()
    if (not isinstance(data["server_ip"], str) or "%" in data["server_ip"] or str(address) != data["server_ip"]
            or type(data["allow_private_network"]) is not bool
            or address.is_unspecified or address.is_multicast or address.is_link_local
            or (address.is_reserved and not address.is_loopback)
            or (not address.is_global and not data["allow_private_network"])):
        reject()
    if type(data["server_port"]) is not int or not 1 <= data["server_port"] <= 65535:
        reject()
    name = data["query_name"]
    if (not isinstance(name, str) or not 1 <= len(name) <= 253
            or not all(LABEL.fullmatch(label) for label in name.removesuffix(".").split("."))):
        reject()
    return data


def _interpret(dns, query, wire, expected):
    base = {"outcome": "invalid-response", "dns_response_observed": False,
        "authoritative_flag": None, "rcode": None, "answer_records": None,
        "expected_answer_match": None, "returned_a_count": None, "returned_a_sha256": None}
    try:
        response = dns.message.from_wire(wire, ignore_trailing=False)
    except (dns.exception.DNSException, ValueError, OverflowError):
        return base
    # is_response permits empty questions on some error codes; this command
    # deliberately requires the exact question even on REFUSED/SERVFAIL replies.
    if (not query.is_response(response) or len(response.question) != 1 or response.question != query.question
            or response.flags & dns.flags.RD):
        return {**base, "outcome": "mismatched-response"}
    if response.flags & 0x0040 or response.edns != -1 or response.had_tsig:
        return base  # Unsupported reserved bit, unsolicited EDNS or signed message.
    base.update(outcome="truncated" if response.flags & dns.flags.TC else "dns-response",
        dns_response_observed=True, authoritative_flag=bool(response.flags & dns.flags.AA),
        rcode=dns.rcode.to_text(response.rcode()), answer_records=sum(len(rr) for rr in response.answer))
    if response.flags & dns.flags.TC or not base["authoritative_flag"] or response.rcode() != dns.rcode.NOERROR:
        return base
    # Compare only a complete direct A RRset. CNAMEs, referrals and mixed answer
    # contexts remain unassessed; no secondary queries or alias following.
    if len(response.answer) != 1:
        return base
    rr = response.answer[0]
    if rr.name != query.question[0].name or rr.rdclass != dns.rdataclass.IN or rr.rdtype != dns.rdatatype.A:
        return base
    values = sorted({item.address for item in rr})
    if values:
        base.update(expected_answer_match=values == sorted(expected), returned_a_count=len(values),
                    returned_a_sha256=digest(values))
    return base


def inspect_dns(input_file, *, authorized=False):
    if authorized is not True:
        raise PermissionError("UDP DNS inspection requires --authorized and written endpoint/query permission")
    path = _approved_file(input_file)
    raw = read_bounded(path, 16384)
    try:
        contract = validate_contract(_decode_json(raw))
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise ValueError("Invalid exact UDP DNS contract; private values withheld") from None
    dns = _engine()
    query = dns.message.make_query(contract["query_name"], dns.rdatatype.A, use_edns=False, flags=0)
    wire = query.to_wire()
    report = {"engine": "scoped-udp-dns-inspection", "schema_version": 1, "observed_at": utcnow().isoformat(),
        "input_sha256": hashlib.sha256(raw).hexdigest(), "server_sha256": digest([contract["server_ip"], contract["server_port"]]),
        "query_name_sha256": digest(contract["query_name"]), "dnspython_version": version("dnspython"),
        "transport": "udp", "server_port": contract["server_port"], "request_budget": 1,
        "datagrams_attempted": 0, "datagrams_sent": 0, "request_bytes": len(wire),
        "response_datagrams": 0, "response_bytes": None, "datagram_complete": None, "response_sha256": None,
        "outcome": "inconclusive", "dns_response_observed": False, "authoritative_flag": None,
        "rcode": None, "answer_records": None, "expected_answer_match": None,
        "returned_a_count": None, "returned_a_sha256": None,
        "port_state": "unclassified", "delivery_verified": False, "dnssec_verified": False, "server_identity_verified": False,
        "service_product_verified": False, "findings": [], "limitations": [
            "One connected-UDP nonrecursive IN A question to one numeric endpoint; no bootstrap DNS, retries, TCP fallback, aliases, referrals or other targets",
            "At most one reply, capped at 512 bytes; oversized, truncated, unsupported and uncorrelated replies do not establish answer consistency",
            "Only an authoritative-flagged NOERROR direct A RRset is compared with owner expectations; AA/AD flags do not authenticate the server or validate DNSSEC",
            "A timeout does not distinguish open, closed or filtered UDP; transport failure and answer mismatch are not automatic vulnerabilities",
            "No recursion/amplification test, zone transfer, update, version query, subnet/port sweep, OS fingerprint, AD or access-path assessment",
            "Three-second send/receive deadline bounded by contract expiry; optional cooperating host-local quota and operator attestation only",
            "Hashes and local receipts do not prove provenance, owner consent, DNS data authenticity or real-world effectiveness"]}
    with shared_quota.invocation(1) as admission:
        report["shared_quota"] = admission.receipt
        family = socket.AF_INET6 if ipaddress.ip_address(contract["server_ip"]).version == 6 else socket.AF_INET
        deadline = time.monotonic() + min(3.0, (_expiry(contract["expires_at"]) - utcnow()).total_seconds())
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as channel:
                admission.ensure_active()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                channel.settimeout(remaining)
                channel.connect((contract["server_ip"], contract["server_port"]))
                validate_contract(contract)
                if read_bounded(_approved_file(input_file), 16384) != raw:
                    raise ValueError("UDP DNS contract changed before transmission")
                admission.ensure_active()
                remaining = min(deadline - time.monotonic(), (_expiry(contract["expires_at"]) - utcnow()).total_seconds())
                if remaining <= 0:
                    raise TimeoutError
                channel.settimeout(remaining)
                report["datagrams_attempted"] = 1
                if channel.send(wire) != len(wire):
                    report["outcome"] = "send-incomplete"
                    return report
                report["datagrams_sent"] = 1
                remaining = min(deadline - time.monotonic(), (_expiry(contract["expires_at"]) - utcnow()).total_seconds())
                if remaining <= 0:
                    raise TimeoutError
                channel.settimeout(remaining)
                reply = channel.recv(513)
                report.update(response_datagrams=1, response_bytes=len(reply))
                if len(reply) > 512:
                    report["outcome"] = "oversized-response"
                    report["datagram_complete"] = False
                else:
                    report["datagram_complete"] = True
                    report["response_sha256"] = hashlib.sha256(reply).hexdigest()
                    report.update(_interpret(dns, query, reply, contract["expected_ipv4"]))
        except shared_quota.QuotaStopped:
            report["outcome"] = "quota-stopped"
        except TimeoutError:
            report["outcome"] = "timeout"
        except (ConnectionRefusedError, ConnectionResetError):
            report["outcome"] = "refused-or-unreachable"
        except OSError as exc:
            report["outcome"] = "oversized-response" if getattr(exc, "winerror", None) == 10040 else "unreachable"
            if report["outcome"] == "oversized-response":
                report["response_datagrams"] = 1
                report["datagram_complete"] = False
    return report
