"""Literal-wire owned UDP controls; no external resolver or scanned network."""
import copy
import hashlib
import json
import socket
import struct
import threading
from contextlib import contextmanager
from datetime import timedelta
from importlib.metadata import PackageNotFoundError

import pytest

from hunterqa import udp_dns_inspection as module
from hunterqa.cli import main
from hunterqa.engagement import utcnow


@pytest.fixture
def contract(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    def forbidden(*args, **kwargs):
        pytest.fail("UDP inspection performed bootstrap DNS resolution")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    value = {"schema_version": 1, "transport": "udp-dns", "authorization_reference": "Written owner DNS canary permission",
        "acknowledged_authorization": True, "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(),
        "server_ip": "127.0.0.1", "server_port": 5353, "query_name": "canary.owner.test.",
        "expected_ipv4": ["192.0.2.10"], "allow_private_network": True}
    path = tmp_path / "dns-contract.json"
    def save(**changes):
        value.update(changes)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path
    save()
    return path, value, save


def response_wire(query, mode):
    """Construct replies with struct/literal RFC 1035 fields, independently of dnspython."""
    ident = struct.unpack_from("!H", query)[0]
    flags, qd, an = 0x8400, 1, 1
    question = query[12:]
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 10])
    if mode == "wrong-answer":
        record = record[:-1] + b"\x0b"
    elif mode == "non-authoritative":
        flags = 0x8000
    elif mode == "truncated":
        flags, an, record = 0x8600, 0, b""
    elif mode == "refused":
        flags, an, record = 0x8005, 0, b""
    elif mode == "nxdomain":
        flags, an, record = 0x8403, 0, b""
    elif mode == "wrong-id":
        ident ^= 1
    elif mode == "wrong-question":
        question = question.replace(b"owner", b"other")
    elif mode == "wrong-type":
        question = question[:-4] + struct.pack("!HH", 28, 1)
    elif mode == "empty-question":
        qd, an, question, record = 0, 0, b"", b""
    elif mode == "query-instead-of-reply":
        flags = 0x0400
    elif mode == "wrong-opcode":
        flags |= 0x0800
    elif mode == "reserved-bit":
        flags |= 0x0040
    elif mode == "unexpected-rd":
        flags |= 0x0100
    elif mode == "compression-loop":
        question, an, record = b"\xc0\x0c\0\1\0\1", 0, b""
    elif mode == "cname":
        alias = b"\x05alias\x05owner\x04test\0"
        record = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(alias)) + alias
    elif mode == "unrelated-answer":
        record = b"\x05other\x05owner\x04test\0" + record[2:]
    elif mode == "empty-answer":
        an, record = 0, b""
    elif mode == "short":
        return query[:5]
    reply = struct.pack("!HHHHHH", ident, flags, qd, an, 0, 0) + question + record
    if mode == "trailing":
        reply += b"private unparsed trailing data"
    if mode == "oversized":
        reply += b"x" * 600
    return reply


@contextmanager
def owned_server(mode="valid", *, rogue=False):
    channel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    channel.bind(("127.0.0.1", 0))
    channel.settimeout(5)
    port, queries, errors = channel.getsockname()[1], [], []
    def serve():
        try:
            query, peer = channel.recvfrom(512)
            queries.append(query)
            if rogue:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
                    other.sendto(response_wire(query, "wrong-answer"), peer)
            if mode != "silent":
                channel.sendto(response_wire(query, mode), peer)
        except Exception as exc:
            errors.append(type(exc).__name__)
        finally:
            channel.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, queries
    finally:
        thread.join(6)
        channel.close()
        assert not thread.is_alive() and not errors


@pytest.mark.parametrize("mode,outcome,match", [
    ("valid", "dns-response", True), ("wrong-answer", "dns-response", False),
    ("non-authoritative", "dns-response", None), ("refused", "dns-response", None),
    ("nxdomain", "dns-response", None), ("truncated", "truncated", None),
    ("wrong-id", "mismatched-response", None), ("wrong-question", "mismatched-response", None),
    ("wrong-type", "mismatched-response", None), ("empty-question", "mismatched-response", None),
    ("query-instead-of-reply", "mismatched-response", None), ("wrong-opcode", "mismatched-response", None),
    ("unexpected-rd", "mismatched-response", None), ("reserved-bit", "invalid-response", None),
    ("compression-loop", "invalid-response", None), ("short", "invalid-response", None),
    ("cname", "dns-response", None), ("unrelated-answer", "dns-response", None),
    ("empty-answer", "dns-response", None), ("trailing", "invalid-response", None),
    ("oversized", "oversized-response", None)])
def test_actual_udp_literal_wire_controls(contract, mode, outcome, match):
    pytest.importorskip("dns")
    path, _, save = contract
    with owned_server(mode) as (port, queries):
        save(server_port=port)
        report = module.inspect_dns(path, authorized=True)
    assert report["outcome"] == outcome and report["expected_answer_match"] is match
    assert report["datagrams_attempted"] == report["datagrams_sent"] == 1
    assert report["response_datagrams"] == 1 and len(queries) == 1
    # Independent request-header and question checks: RD=0, no EDNS/additional,
    # one IN A question, no ANY, AXFR, version.bind or update request.
    assert struct.unpack("!HHHHH", queries[0][2:12]) == (0, 1, 0, 0, 0)
    assert queries[0][12:] == b"\x06canary\x05owner\x04test\0\0\1\0\1"
    if match is not None:
        assert report["authoritative_flag"] is True and report["returned_a_count"] == 1
    else:
        assert report["returned_a_count"] is None and report["returned_a_sha256"] is None
    assert report["port_state"] == "unclassified" and not report["dnssec_verified"]
    assert not report["server_identity_verified"] and not report["delivery_verified"] and report["findings"] == []
    serialized = json.dumps(report)
    for private in ("127.0.0.1", "192.0.2.10", "192.0.2.11", "owner.test", str(path), "Written owner"):
        assert private not in serialized


def test_connected_socket_ignores_other_source_port(contract):
    pytest.importorskip("dns")
    with owned_server(rogue=True) as (port, queries):
        contract[2](server_port=port)
        report = module.inspect_dns(contract[0], authorized=True)
    assert report["expected_answer_match"] is True and report["response_datagrams"] == 1 and len(queries) == 1


def test_timeout_does_not_classify_udp_port(contract):
    pytest.importorskip("dns")
    with owned_server("silent") as (port, _):
        contract[2](server_port=port)
        report = module.inspect_dns(contract[0], authorized=True)
    assert report["outcome"] in ("timeout", "refused-or-unreachable")
    assert report["port_state"] == "unclassified" and report["expected_answer_match"] is None
    assert report["datagrams_sent"] == 1 and not report["dns_response_observed"]


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("transport", "tcp"), ("acknowledged_authorization", 1),
    ("authorization_reference", ""), ("authorization_reference", "private\nreference"),
    ("server_ip", "resolver.owner.test"), ("server_ip", "http://127.0.0.1"),
    ("server_ip", "0.0.0.0"), ("server_ip", "224.0.0.1"), ("server_ip", "169.254.169.254"),
    ("server_ip", "255.255.255.255"), ("server_ip", "fe80::1%eth0"),
    ("server_ip", "2606:4700:4700::1111%eth0"), ("server_ip", 2130706433),
    ("server_port", True), ("server_port", 0), ("server_port", 65536),
    ("allow_private_network", 1), ("allow_private_network", False),
    ("query_name", "*.owner.test"), ("query_name", "Upper.owner.test"),
    ("query_name", "_srv.owner.test"), ("query_name", "."), ("query_name", "a..owner.test"),
    ("query_name", "-bad.owner.test"), ("query_name", "x" * 64 + ".test"),
    ("expected_ipv4", []), ("expected_ipv4", ["192.0.2.10", "192.0.2.10"]),
    ("expected_ipv4", ["::1"]), ("expected_ipv4", [True]), ("expected_ipv4", ["secret.invalid"]),
    ("expires_at", "2020-01-01T00:00:00+00:00"), ("expires_at", "2030-01-01T00:00:00+00:00"),
    ("expires_at", "2026-10-31T00:00:00"), ("expires_at", 7)])
def test_invalid_contract_never_opens_socket(contract, monkeypatch, field, value):
    contract[2](**{field: value})
    monkeypatch.setattr(socket, "socket", lambda *a: pytest.fail("Invalid contract opened socket"))
    with pytest.raises(ValueError, match="private values withheld"):
        module.inspect_dns(contract[0], authorized=True)


@pytest.mark.parametrize("authorized", [False, None, "yes", 1])
def test_permission_precedes_input_access(authorized):
    with pytest.raises(PermissionError):
        module.inspect_dns("does-not-exist", authorized=authorized)


def test_duplicate_keys_and_oversized_contract_rejected(contract, monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a: pytest.fail("Malformed input opened socket"))
    for raw in ('{"schema_version":1,"schema_version":1}', 'x' * 16385):
        contract[0].write_text(raw)
        with pytest.raises(ValueError):
            module.inspect_dns(contract[0], authorized=True)


def test_absent_optional_dependency_fails_before_socket(contract, monkeypatch):
    def missing(name):
        raise PackageNotFoundError(name)
    monkeypatch.setattr(module, "version", missing)
    monkeypatch.setattr(socket, "socket", lambda *a: pytest.fail("Missing dependency opened socket"))
    with pytest.raises(RuntimeError, match=r"Install .\[network\]"):
        module.inspect_dns(contract[0], authorized=True)


def test_no_wildcards_extra_fields_and_schema_unknowns(contract):
    original = contract[1]
    for data in ({**original, "extra": True}, {k: v for k, v in original.items() if k != "expected_ipv4"}, [], None):
        with pytest.raises(ValueError):
            module.validate_contract(data)
    assert module.validate_contract(copy.deepcopy(original)) == original


def test_contract_changed_after_review_sends_nothing(contract, monkeypatch):
    pytest.importorskip("dns")
    sent = []
    class ChangedSocket:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass
        def settimeout(self, seconds):
            assert 0 < seconds <= 3
        def connect(self, address):
            contract[2](query_name="changed.owner.test.")
        def send(self, wire):
            sent.append(wire)
    monkeypatch.setattr(socket, "socket", lambda *a: ChangedSocket())
    with pytest.raises(ValueError, match="changed before transmission"):
        module.inspect_dns(contract[0], authorized=True)
    assert sent == []


def test_expiry_bounds_and_explicit_public_or_private_address_policy(contract):
    now = utcnow()
    data = {**contract[1], "expires_at": (now + timedelta(hours=24)).isoformat()}
    assert module.validate_contract(data, now=now) == data
    for expiry in (now, now - timedelta(seconds=1), now + timedelta(hours=24, seconds=1)):
        with pytest.raises(ValueError):
            module.validate_contract({**data, "expires_at": expiry.isoformat()}, now=now)
    assert module.validate_contract({**data, "server_ip": "8.8.8.8", "allow_private_network": False}, now=now)
    assert module.validate_contract({**data, "server_ip": "::1"}, now=now)


def test_numeric_ipv6_family_and_total_deadline_after_send(contract, monkeypatch):
    pytest.importorskip("dns")
    contract[2](server_ip="::1")
    times = iter([100.0, 100.1, 100.2, 104.0])
    sent, families, closed = [], [], []
    class TimedSocket:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            closed.append(True)
        def settimeout(self, seconds):
            assert 0 < seconds <= 3
        def connect(self, address):
            assert address == ("::1", 5353)
        def send(self, wire):
            sent.append(wire)
            return len(wire)
        def recv(self, size):
            pytest.fail("Expired total deadline entered receive")
    def factory(family, kind):
        families.append((family, kind))
        return TimedSocket()
    monkeypatch.setattr(socket, "socket", factory)
    monkeypatch.setattr(module.time, "monotonic", lambda: next(times))
    report = module.inspect_dns(contract[0], authorized=True)
    assert families == [(socket.AF_INET6, socket.SOCK_DGRAM)] and len(sent) == 1 and closed == [True]
    assert report["outcome"] == "timeout" and report["response_datagrams"] == 0


def test_old_optional_dependency_rejected(contract, monkeypatch):
    monkeypatch.setattr(module, "version", lambda name: "2.9.0")
    monkeypatch.setattr(socket, "socket", lambda *a: pytest.fail("Old dependency opened socket"))
    with pytest.raises(RuntimeError, match="dnspython>=2.9.1"):
        module.inspect_dns(contract[0], authorized=True)


@pytest.mark.parametrize("error,outcome", [(TimeoutError(), "timeout"),
    (ConnectionRefusedError(), "refused-or-unreachable"), (OSError("private-error-address"), "unreachable")])
def test_transport_exceptions_do_not_leak_or_retry(contract, monkeypatch, error, outcome):
    pytest.importorskip("dns")
    calls = []
    class FailedSocket:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass
        def settimeout(self, seconds):
            assert 0 < seconds <= 3
        def connect(self, address):
            calls.append(address)
            raise error
    monkeypatch.setattr(socket, "socket", lambda *a: FailedSocket())
    report = module.inspect_dns(contract[0], authorized=True)
    assert report["outcome"] == outcome and calls == [("127.0.0.1", 5353)]
    assert report["datagrams_attempted"] == 0 and report["expected_answer_match"] is None
    assert "private-error-address" not in json.dumps(report)


def test_cli_private_create_only_receipt(contract, tmp_path):
    pytest.importorskip("dns")
    output = tmp_path / "udp-receipt.json"
    with owned_server() as (port, _):
        contract[2](server_port=port)
        main(["udp-dns-inspect", "--input", str(contract[0]), "--out", str(output), "--authorized"])
    report = json.loads(output.read_text())
    assert report["expected_answer_match"] is True
    assert report["input_sha256"] == hashlib.sha256(contract[0].read_bytes()).hexdigest()
    with pytest.raises(FileExistsError):
        main(["udp-dns-inspect", "--input", str(contract[0]), "--out", str(output), "--authorized"])
