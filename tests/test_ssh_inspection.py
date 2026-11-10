"""Owned TCP services, hostile identification data, scope and quota controls."""
import hashlib
import json
import socket
import threading
from contextlib import contextmanager
from datetime import timedelta

import pytest

from hunterqa import shared_quota as quota
from hunterqa import ssh_inspection as module
from hunterqa.cli import main
from hunterqa.engagement import utcnow


@pytest.fixture
def contract(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER", raising=False)
    data = {"schema_version": 1, "transport": "tcp-ssh-identification",
        "authorization_reference": "Owned loopback endpoint permission",
        "acknowledged_authorization": True, "expires_at": (utcnow() + timedelta(hours=1)).isoformat(),
        "server_ip": "127.0.0.1", "server_port": 22, "allow_private_network": True}
    path = tmp_path / "ssh-contract.json"
    def save(**changes):
        data.update(changes)
        path.write_text(json.dumps(data), encoding="utf-8")
        return path
    save()
    return path, save


@contextmanager
def server(payload, *, family=socket.AF_INET):
    listener = socket.socket(family, socket.SOCK_STREAM)
    try:
        listener.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
    except OSError:
        listener.close()
        if family == socket.AF_INET6:
            pytest.skip("IPv6 loopback unavailable")
        raise
    listener.listen(1)
    listener.settimeout(5)
    received, errors = [], []
    def serve():
        try:
            with listener.accept()[0] as peer:
                peer.settimeout(5)
                peer.sendall(payload)
                received.append(peer.recv(1))
        except (ConnectionResetError, BrokenPipeError):
            received.append(b"")
        except Exception as exc:
            errors.append(type(exc).__name__)
        finally:
            listener.close()
    port = listener.getsockname()[1]
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, received
    finally:
        thread.join(6)
        listener.close()
        assert not thread.is_alive() and not errors


@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
def test_actual_owned_server_never_receives_client_data(contract, family, monkeypatch):
    line = b"SSH-2.0-OpenSSH_9.6p1 private-tenant-build\r\n"
    with server(b"Private preamble\r\n" + line + b"\x00\x00binary-key-exchange", family=family) as (port, received):
        path = contract[1](server_port=port, server_ip="::1" if family == socket.AF_INET6 else "127.0.0.1")
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("Numeric SSH used DNS"))
        report = module.inspect_ssh(path, authorized=True)
    assert received == [b""] and report["application_bytes_sent"] == 0
    assert report["outcome"] == "identification-observed" and report["advertised_protocol"] == "2.0"
    assert report["advertised_product_hint"] == "OpenSSH" and report["pre_identification_lines"] == 1
    assert report["identification_sha256"] == hashlib.sha256(line).hexdigest()
    assert not report["server_identity_verified"] and not report["service_product_verified"]
    assert not report["vulnerability_verified"] and report["findings"] == []
    for private in ("127.0.0.1", "::1", "private-tenant-build", "OpenSSH_9.6p1", "Private preamble", str(path)):
        assert private not in json.dumps(report)


class Stream:
    def __init__(self, chunks, *, connect=None, before_read=None):
        self.chunks = list(chunks)
        self.connect_hook, self.read_hook = connect, before_read
        self.connected, self.reads, self.closed = [], [], False
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.closed = True
    def settimeout(self, value):
        assert 0 < value <= 5
    def connect(self, address):
        self.connected.append(address)
        if self.connect_hook:
            self.connect_hook()
    def recv(self, size):
        self.reads.append(size)
        if self.read_hook:
            self.read_hook()
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        if isinstance(value, Exception):
            raise value
        if len(value) > size:
            self.chunks.insert(0, value[size:])
        return value[:size]


def run_stream(contract, monkeypatch, chunks, **kwargs):
    stream = Stream(chunks, **kwargs)
    monkeypatch.setattr(socket, "socket", lambda *a: stream)
    report = module.inspect_ssh(contract[0], authorized=True)
    assert stream.closed
    return report, stream


@pytest.mark.parametrize("chunks,expected", [
    ([b"S", b"SH-", b"2.0-dropbear_2024.86\r", b"\n"], "identification-observed"),
    ([b"SSH-1.99-libssh_0.11\r\n"], "identification-observed"),
    ([b"SSH-1.5-test\r\n"], "identification-observed"),
    ([b"SSH-1.3-test\r\n"], "identification-observed"),
    ([b"SSH-3.0-test\r\n"], "unsupported-protocol"),
    ([b"SSH-2.0-soft-ware\r\n"], "invalid-identification"),
    ([b"SSH-2.0-\r\n"], "invalid-identification"),
    ([b"SSH-2.0-test\n"], "invalid-identification"),
    ([b"SSH-2.0-test\x00\r\n"], "invalid-identification"),
    ([b"SSH-2.0-test\tcomment\r\n"], "invalid-identification"),
    ([b"SSH-2.0-test \x1b[31mprivate\r\n"], "invalid-identification"),
    ([b"SSH-2.0-test \xff\r\n"], "invalid-identification"),
    ([b"x" * 256], "line-limit"),
    ([b"x" * 254 + b"\r\n"], "invalid-identification"),
    ([b"hello\r\n" * 11 + b"SSH-2.0-test\r\n"], "pre-identification-limit"),
    ([b"SSH-2.0-partial"], "closed-before-identification"),
    ([], "closed-before-identification"),
    ([TimeoutError("secret timeout")], "timeout"),
    ([OSError("secret reset")], "unreachable"),
    ([((b"x" * 250) + b"\r\n") * 10], "byte-limit"),
])
def test_fragmented_malformed_bounded_and_closed_streams(contract, monkeypatch, chunks, expected):
    report, stream = run_stream(contract, monkeypatch, chunks)
    assert report["outcome"] == expected
    assert stream.connected == [("127.0.0.1", 22)]
    assert report["received_bytes"] <= 2048 and all(0 < size <= 256 for size in stream.reads)
    assert "secret" not in json.dumps(report)


def test_exact_line_boundary_and_ten_preamble_lines(contract, monkeypatch):
    line = b"SSH-2.0-" + b"s" * 245 + b"\r\n"
    assert len(line) == 255
    report, _ = run_stream(contract, monkeypatch, [b"notice\r\n" * 10 + line])
    assert report["outcome"] == "identification-observed" and report["pre_identification_lines"] == 10


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("transport", "tcp"), ("acknowledged_authorization", 1),
    ("authorization_reference", ""), ("authorization_reference", "secret\n"),
    ("expires_at", "2000-01-01T00:00:00Z"), ("expires_at", "2100-01-01T00:00:00Z"),
    ("expires_at", "2026-11-10"), ("expires_at", None),
    ("server_port", True), ("server_port", 0), ("server_port", 65536),
    ("server_ip", "localhost"), ("server_ip", "127.0.0.01"), ("server_ip", 2130706433),
    ("server_ip", "0.0.0.0"), ("server_ip", "224.0.0.1"), ("server_ip", "169.254.1.1"),
    ("server_ip", "240.0.0.1"), ("server_ip", "::"), ("server_ip", "ff02::1"),
    ("server_ip", "fe80::1"), ("server_ip", "::1%lo"), ("allow_private_network", False),
    ("allow_private_network", "true"), ("extra", "secret-value")])
def test_invalid_contract_never_creates_socket(contract, monkeypatch, field, value):
    contract[1](**{field: value})
    monkeypatch.setattr(socket, "socket", lambda *a: pytest.fail("Invalid contract reached transport"))
    with pytest.raises(ValueError, match="private values withheld"):
        module.inspect_ssh(contract[0], authorized=True)


def test_authorization_and_approved_input_required(contract, tmp_path, monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a: pytest.fail("Missing authorization reached transport"))
    with pytest.raises(PermissionError):
        module.inspect_ssh(contract[0])
    (tmp_path / "other").mkdir()
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path / "other"))
    with pytest.raises(ValueError):
        module.inspect_ssh(contract[0], authorized=True)


@pytest.mark.parametrize("mutation", ["change", "remove", "expire"])
def test_contract_rechecked_after_connect_before_read(contract, monkeypatch, mutation):
    def change():
        if mutation == "remove":
            contract[0].unlink()
        else:
            contract[1](**({"server_port": 23} if mutation == "change" else {"expires_at": "2000-01-01T00:00:00Z"}))
    report, stream = run_stream(contract, monkeypatch, [b"SSH-2.0-test\r\n"], connect=change)
    assert report["outcome"] == "contract-stopped" and not stream.reads


def test_combined_deadline_not_reset_per_read(contract, monkeypatch):
    times = iter([100.0, 100.0, 101.0, 106.0])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(times))
    report, stream = run_stream(contract, monkeypatch, [b"S", b"SH-2.0-test\r\n"])
    assert report["outcome"] == "timeout" and len(stream.reads) == 1


@pytest.mark.parametrize("payload", [b"{", b"[]", b"{\"schema_version\":1,\"schema_version\":1}", b"x" * 16385])
def test_malformed_duplicate_and_oversized_inputs_block_transport(contract, monkeypatch, payload):
    contract[0].write_bytes(payload)
    monkeypatch.setattr(socket, "socket", lambda *a: pytest.fail("Bad input reached transport"))
    with pytest.raises(ValueError):
        module.inspect_ssh(contract[0], authorized=True)


@pytest.mark.parametrize("error,expected", [(ConnectionRefusedError("private refused"), "refused"),
    (TimeoutError("private timeout"), "timeout"), (OSError("private unreachable"), "unreachable")])
def test_connect_errors_do_not_retry_or_leak(contract, monkeypatch, error, expected):
    def fail():
        raise error
    report, stream = run_stream(contract, monkeypatch, [], connect=fail)
    assert report["outcome"] == expected and len(stream.connected) == 1 and not stream.reads
    assert "private refused" not in json.dumps(report) and "private timeout" not in json.dumps(report)
    assert "private unreachable" not in json.dumps(report)


@pytest.fixture
def ledger(contract, tmp_path, monkeypatch):
    path = tmp_path / "quota.sqlite3"
    quota.initialize(path, max_requests=1, max_active_runs=1,
        expires_at=(utcnow() + timedelta(hours=1)).isoformat(), authorized=True)
    monkeypatch.setenv("HUNTERQA_QUOTA_LEDGER", str(path))
    return path


def test_shared_quota_release_no_refund_and_second_call_denied(contract, ledger, monkeypatch):
    def active():
        state = quota.status(ledger)
        assert state["active_runs"] == 1 and state["charged_requests"] == 1
    report, _ = run_stream(contract, monkeypatch, [b"SSH-2.0-test\r\n"], connect=active)
    assert report["shared_quota"]["reservation_released"] is True
    assert quota.status(ledger)["active_runs"] == 0 and quota.status(ledger)["charged_requests"] == 1
    monkeypatch.setattr(socket, "socket", lambda *a: pytest.fail("Exhausted quota reached transport"))
    with pytest.raises(PermissionError):
        module.inspect_ssh(contract[0], authorized=True)
    assert str(ledger) not in json.dumps(report)


@pytest.mark.parametrize("mutation", ["stop", "unset"])
def test_quota_stop_before_next_read(contract, ledger, monkeypatch, mutation):
    def change():
        if mutation == "stop":
            quota.stop(ledger, authorized=True)
        else:
            monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER")
    report, stream = run_stream(contract, monkeypatch, [b"SSH-2.0-test\r\n"], connect=change)
    assert report["outcome"] == "quota-stopped" and not stream.reads
    assert report["shared_quota"]["reservation_released"] is True


def test_quota_failure_releases_slot_but_retains_charge(contract, ledger, monkeypatch):
    report, _ = run_stream(contract, monkeypatch, [TimeoutError()])
    assert report["outcome"] == "timeout" and report["shared_quota"]["reservation_released"] is True
    state = quota.status(ledger)
    assert state["active_runs"] == 0 and state["charged_requests"] == 1


def test_quota_checked_between_fragmented_reads(contract, ledger, monkeypatch):
    def change():
        quota.stop(ledger, authorized=True)
    report, stream = run_stream(contract, monkeypatch, [b"S", b"SH-2.0-test\r\n"], before_read=change)
    assert report["outcome"] == "quota-stopped" and len(stream.reads) == 1


def test_invalid_input_does_not_consume_quota(contract, ledger, monkeypatch):
    contract[1](server_port=0)
    with pytest.raises(ValueError):
        module.inspect_ssh(contract[0], authorized=True)
    state = quota.status(ledger)
    assert state["active_runs"] == 0 and state["charged_requests"] == 0


def test_cli_owned_transport_and_create_only_output(contract, tmp_path):
    output = tmp_path / "ssh-receipt.json"
    with server(b"SSH-2.0-test\r\n") as (port, received):
        contract[1](server_port=port)
        main(["ssh-service-inspect", "--input", str(contract[0]), "--out", str(output), "--authorized"])
    assert json.loads(output.read_text())["outcome"] == "identification-observed" and received == [b""]
    before = output.read_bytes()
    with pytest.raises(FileExistsError):
        main(["ssh-service-inspect", "--input", str(contract[0]), "--out", str(output), "--authorized"])
    assert output.read_bytes() == before


def test_cli_unapproved_output_blocks_execution(contract, tmp_path, monkeypatch):
    monkeypatch.setattr(module, "inspect_ssh", lambda *a, **k: pytest.fail("Unapproved output reached transport"))
    with pytest.raises(ValueError):
        main(["ssh-service-inspect", "--input", str(contract[0]), "--out", str(tmp_path.parent / "outside.json"), "--authorized"])
