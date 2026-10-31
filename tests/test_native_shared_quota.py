"""Native-command admission and independent-process quota conservation controls."""
import json
import multiprocessing
import os
import queue
import socket
import sqlite3
import struct
import threading
from datetime import timedelta

import pytest

from hunterqa import shared_quota as quota
from hunterqa import azure_inventory as azure
from hunterqa import gcp_inventory as gcp
from hunterqa import tls_inspection as tls
from hunterqa import udp_dns_inspection as udp
from hunterqa.engagement import utcnow

SUB = "11111111-2222-3333-4444-555555555555"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TOKEN = "synthetic-private-token-0123456789"


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    path = tmp_path / "private-native-quota.sqlite3"
    quota.initialize(path, max_requests=12, max_active_runs=3,
        expires_at=(utcnow() + timedelta(hours=1)).isoformat(), authorized=True)
    monkeypatch.setenv("HUNTERQA_QUOTA_LEDGER", str(path))
    return path


def _files(tmp_path, kind):
    source, secret = tmp_path / (kind + ".json"), tmp_path / (kind + "-secret.json")
    expiry = (utcnow() + timedelta(minutes=10)).isoformat()
    if kind == "tls":
        data = {"program": "Owned native quota fixture", "platform": "private",
            "authorization_reference": "Written fixture permission", "acknowledged_authorization": True,
            "allowed_hosts": ["owned.example.test"], "allowed_ports": [443], "allowed_paths": ["/"],
            "methods": ["HEAD"], "max_requests": 1, "interval_seconds": 0.5}
    elif kind == "udp":
        data = {"schema_version": 1, "transport": "udp-dns", "authorization_reference": "Written fixture permission",
            "acknowledged_authorization": True, "expires_at": expiry, "server_ip": "127.0.0.1", "server_port": 5353,
            "query_name": "owned.example.test.", "expected_ipv4": ["192.0.2.10"], "allow_private_network": True}
    else:
        data = {"schema_version": 1, "provider": kind, "authorization_reference": "Written fixture permission",
            "acknowledged_authorization": True, "expires_at": expiry, "max_pages": 2,
            "page_size": 2, "max_resources": 4, "interval_seconds": 0.5}
        if kind == "azure":
            data.update(subscription_id=SUB, tenant_id=TENANT)
        else:
            data.update(project_id="owned-fixture-123", project_number="123456789012", expected_parent="folders/123",
                read_time=(utcnow() - timedelta(seconds=2)).isoformat(timespec="microseconds").replace("+00:00", "Z"))
    source.write_text(json.dumps(data), encoding="utf-8")
    secret.write_text(json.dumps({"access_token": TOKEN, "expires_at": expiry}), encoding="utf-8")
    return source, secret, data


def _cloud_run(tmp_path, kind, transport):
    source, secret, data = _files(tmp_path, kind)
    module = azure if kind == "azure" else gcp
    return module.inventory(source, secret, authorized=True, transport=transport(data), sleeper=lambda _: None)


def _response(data):
    return {"status": 200, "body": json.dumps(data).encode()}


def _context(kind, data):
    if kind == "azure":
        return {"id": "/subscriptions/" + SUB, "subscriptionId": SUB, "tenantId": TENANT}
    return {"name": "projects/" + data["project_number"], "projectId": data["project_id"],
            "parent": data["expected_parent"], "state": "ACTIVE"}


def _empty_page(kind, data):
    return {"value": []} if kind == "azure" else {"assets": [], "readTime": gcp._read_time(data["read_time"])}


def test_invocation_unconfigured_is_explicit_and_setting_change_stops(monkeypatch):
    monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER", raising=False)
    with quota.invocation(3) as lease:
        assert lease.receipt["configured"] is False and lease.receipt["reservation_id"] is None
        lease.ensure_active()
        monkeypatch.setenv("HUNTERQA_QUOTA_LEDGER", "new-configured-ledger")
        with pytest.raises(quota.QuotaStopped):
            lease.ensure_active()
    assert lease.receipt["release_state"] == "not-configured"


def test_reservation_and_exception_release_keep_full_charge(ledger):
    with pytest.raises(RuntimeError):
        with quota.invocation(5) as lease:
            assert quota.status(ledger)["active_runs"] == 1
            raise RuntimeError("owned fixture failure")
    state = quota.status(ledger)
    assert state["active_runs"] == 0 and state["charged_requests"] == 5
    assert lease.receipt["reservation_released"] is True
    assert str(ledger) not in json.dumps(lease.receipt)


@pytest.mark.parametrize("change", ["stop", "unset", "configuration", "reconcile"])
def test_active_invocation_fails_closed_after_control_change(ledger, monkeypatch, change):
    with quota.invocation(2) as lease:
        if change == "stop":
            quota.stop(ledger, authorized=True)
        elif change == "unset":
            monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER")
        elif change == "configuration":
            with sqlite3.connect(ledger) as db:
                db.execute("UPDATE configuration SET max_requests=11")
        else:
            quota.reconcile(ledger, lease.run_id, authorized=True)
        with pytest.raises(quota.QuotaStopped):
            lease.ensure_active()
    assert quota.status(ledger)["active_runs"] == 0
    assert quota.status(ledger)["charged_requests"] == 2


def test_check_error_does_not_leak_ledger_or_resume(ledger, monkeypatch):
    with quota.invocation(1) as lease:
        def invalid(*args):
            raise sqlite3.OperationalError("private-ledger-path")
        monkeypatch.setattr(quota, "check", invalid)
        with pytest.raises(quota.QuotaStopped) as error:
            lease.ensure_active()
        assert "private-ledger-path" not in str(error.value)
    assert lease.receipt["reservation_released"] is True


def test_cleanup_failure_retains_receipt_and_requires_manual_reconciliation(ledger, monkeypatch):
    with monkeypatch.context() as patch:
        def failed(*args):
            raise sqlite3.OperationalError("private-ledger-path")
        patch.setattr(quota, "release", failed)
        with quota.invocation(2) as lease:
            lease.ensure_active()
    assert lease.receipt["reservation_released"] is False
    assert lease.receipt["release_state"] == "manual-reconciliation-required"
    assert "private-ledger-path" not in json.dumps(lease.receipt)
    assert quota.status(ledger)["active_runs"] == 1
    # The invocation is over before explicit recovery; the charge is preserved.
    quota.reconcile(ledger, lease.run_id, authorized=True)
    assert quota.status(ledger)["active_runs"] == 0 and quota.status(ledger)["charged_requests"] == 2


@pytest.mark.parametrize("budget", [0, 41, True, 1.5])
def test_invalid_reservation_never_charges(ledger, budget):
    with pytest.raises(ValueError):
        with quota.invocation(budget):
            pytest.fail("Invalid reservation admitted")
    assert quota.status(ledger)["charged_requests"] == 0


@pytest.mark.parametrize("kind", ["tls", "udp", "azure", "gcp"])
def test_exhausted_ledger_blocks_native_command_before_network(ledger, tmp_path, monkeypatch, kind):
    if kind == "udp":
        pytest.importorskip("dns")
    review = quota.configured_review()
    quota.reserve(review, "spent-by-another-client", 12)
    quota.release(review, "spent-by-another-client")
    source, secret, _ = _files(tmp_path, kind)
    def forbidden(*args, **kwargs):
        pytest.fail("Exhausted quota reached target transport")
    monkeypatch.setattr(tls, "resolve_pinned", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(PermissionError, match="exhausted"):
        if kind == "tls":
            tls.inspect_service(source, "https://owned.example.test/", authorized=True)
        elif kind == "udp":
            udp.inspect_dns(source, authorized=True)
        else:
            module = azure if kind == "azure" else gcp
            module.inventory(source, secret, authorized=True, transport=forbidden)
    assert quota.status(ledger)["charged_requests"] == 12 and quota.status(ledger)["active_runs"] == 0


@pytest.mark.parametrize("kind", ["azure", "gcp"])
def test_cloud_commands_reserve_worst_case_and_release_even_if_fewer_pages(ledger, tmp_path, kind):
    calls = []
    def factory(data):
        def transport(target, token, *, before_send):
            before_send()
            state = quota.status(ledger)
            assert state["charged_requests"] == 3 and state["active_runs"] == 1
            calls.append(target)
            return _response(_context(kind, data) if len(calls) == 1 else _empty_page(kind, data))
        return transport
    report = _cloud_run(tmp_path, kind, factory)
    assert len(calls) == 2 and report["shared_quota"]["reserved_requests"] == 3
    assert report["shared_quota"]["reservation_released"] is True
    assert quota.status(ledger)["charged_requests"] == 3 and quota.status(ledger)["active_runs"] == 0
    assert str(ledger) not in json.dumps(report)


@pytest.mark.parametrize("kind", ["azure", "gcp"])
@pytest.mark.parametrize("change", ["stop", "unset"])
def test_cloud_stop_after_context_prevents_next_page(ledger, tmp_path, monkeypatch, kind, change):
    calls = []
    def factory(data):
        def transport(target, token, *, before_send):
            before_send()
            calls.append(target)
            if change == "stop":
                quota.stop(ledger, authorized=True)
            else:
                monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER")
            return _response(_context(kind, data))
        return transport
    report = _cloud_run(tmp_path, kind, factory)
    assert len(calls) == 1 and report["outcome"] == "quota-stopped"
    assert report["requests_attempted"] == 1 and report["shared_quota"]["reservation_released"] is True
    assert quota.status(ledger)["charged_requests"] == 3


@pytest.mark.parametrize("kind", ["azure", "gcp"])
def test_cloud_native_guard_after_tls_prevents_bearer_when_quota_stops(ledger, tmp_path, monkeypatch, kind):
    module = azure if kind == "azure" else gcp
    monkeypatch.setattr(module, "resolve_pinned", lambda *a: "8.8.8.8")
    closed = []
    class Connection:
        def connect(self):
            quota.stop(ledger, authorized=True)
        def request(self, *args, **kwargs):
            pytest.fail("Bearer transmitted after shared stop")
        def close(self):
            closed.append(True)
    monkeypatch.setattr(module, "_ARMConnection" if kind == "azure" else "_GCPConnection", lambda *a: Connection())
    source, secret, _ = _files(tmp_path, kind)
    report = module.inventory(source, secret, authorized=True, sleeper=lambda _: None)
    assert report["outcome"] == "quota-stopped" and closed == [True]
    assert report["requests_completed"] == 0 and report["shared_quota"]["reservation_released"] is True


def test_tls_dns_failure_releases_and_never_refunds(ledger, tmp_path, monkeypatch):
    source, _, _ = _files(tmp_path, "tls")
    def failed(*args):
        assert quota.status(ledger)["active_runs"] == 1
        raise ValueError("Owned DNS failure")
    monkeypatch.setattr(tls, "resolve_pinned", failed)
    with pytest.raises(ValueError, match="Owned DNS"):
        tls.inspect_service(source, "https://owned.example.test/", authorized=True)
    assert quota.status(ledger)["charged_requests"] == 1 and quota.status(ledger)["active_runs"] == 0


def test_udp_stop_between_connect_and_send_keeps_datagram_unsent(ledger, tmp_path, monkeypatch):
    pytest.importorskip("dns")
    source, _, _ = _files(tmp_path, "udp")
    class Channel:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, value):
            assert 0 < value <= 3
        def connect(self, address):
            quota.stop(ledger, authorized=True)
        def send(self, packet):
            pytest.fail("UDP sent after shared stop")
    monkeypatch.setattr(socket, "socket", lambda *a: Channel())
    report = udp.inspect_dns(source, authorized=True)
    assert report["outcome"] == "quota-stopped" and report["datagrams_attempted"] == 0
    assert report["shared_quota"]["reservation_released"] is True


def test_udp_early_send_failure_still_releases_reservation(ledger, tmp_path, monkeypatch):
    pytest.importorskip("dns")
    source, _, _ = _files(tmp_path, "udp")
    class Channel:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, value):
            pass
        def connect(self, address):
            pass
        def send(self, packet):
            return 0
    monkeypatch.setattr(socket, "socket", lambda *a: Channel())
    report = udp.inspect_dns(source, authorized=True)
    assert report["outcome"] == "send-incomplete" and report["shared_quota"]["reservation_released"] is True
    assert quota.status(ledger)["active_runs"] == 0 and quota.status(ledger)["charged_requests"] == 1


def test_real_owned_udp_reply_holds_slot_until_response_and_preserves_charge(ledger, tmp_path):
    pytest.importorskip("dns")
    source, _, data = _files(tmp_path, "udp")
    service = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    service.bind(("127.0.0.1", 0))
    service.settimeout(5)
    data["server_port"] = service.getsockname()[1]
    source.write_text(json.dumps(data))
    observed = []
    def serve():
        try:
            query, peer = service.recvfrom(512)
            observed.append(quota.status(ledger))
            record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + bytes([192, 0, 2, 10])
            service.sendto(query[:2] + struct.pack("!HHHHH", 0x8400, 1, 1, 0, 0) + query[12:] + record, peer)
        finally:
            service.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        report = udp.inspect_dns(source, authorized=True)
    finally:
        thread.join(6)
        service.close()
    assert not thread.is_alive() and len(observed) == 1
    assert observed[0]["active_runs"] == 1 and observed[0]["charged_requests"] == 1
    assert report["expected_answer_match"] is True and report["shared_quota"]["reservation_released"] is True
    assert quota.status(ledger)["active_runs"] == 0 and quota.status(ledger)["charged_requests"] == 1


def test_real_owned_tls_transport_failure_releases_without_refund(ledger, tmp_path, monkeypatch):
    source, _, data = _files(tmp_path, "tls")
    service = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    service.bind(("127.0.0.1", 0))
    service.listen(1)
    service.settimeout(5)
    port, observed = service.getsockname()[1], []
    data["allowed_ports"] = [port]
    source.write_text(json.dumps(data))
    def serve():
        try:
            with service.accept()[0] as peer:
                peer.settimeout(5)
                hello = peer.recv(8192)
                observed.append((hello[:2], quota.status(ledger)))
                peer.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                try:
                    peer.recv(1024)
                except ConnectionResetError:
                    pass
        finally:
            service.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    monkeypatch.setattr(tls, "resolve_pinned", lambda *a: "127.0.0.1")
    try:
        report = tls.inspect_service(source, f"https://owned.example.test:{port}/", authorized=True)
    finally:
        thread.join(6)
        service.close()
    assert not thread.is_alive() and observed[0][0] == b"\x16\x03"
    assert observed[0][1]["active_runs"] == 1 and observed[0][1]["charged_requests"] == 1
    assert report["outcome"] == "tls-error" and report["shared_quota"]["reservation_released"] is True
    assert quota.status(ledger)["active_runs"] == 0 and quota.status(ledger)["charged_requests"] == 1


@pytest.mark.parametrize("kind", ["tls", "udp", "azure", "gcp"])
def test_invalid_input_is_not_charged(ledger, tmp_path, monkeypatch, kind):
    source, secret, _ = _files(tmp_path, kind)
    source.write_text("{}")
    def forbidden(*args):
        pytest.fail("Invalid input attempted shared admission")
    monkeypatch.setattr(quota, "invocation", forbidden)
    with pytest.raises(ValueError):
        if kind == "tls":
            tls.inspect_service(source, "https://owned.example.test/", authorized=True)
        elif kind == "udp":
            udp.inspect_dns(source, authorized=True)
        else:
            module = azure if kind == "azure" else gcp
            module.inventory(source, secret, authorized=True)
    assert quota.status(ledger)["charged_requests"] == 0


def test_workflow_and_native_clients_share_active_run_slots(ledger):
    with sqlite3.connect(ledger) as db:
        db.execute("UPDATE configuration SET max_active_runs=1")
    review = quota.configured_review()
    quota.reserve(review, "held-by-workflow", 0)
    with pytest.raises(PermissionError, match="active-run"):
        with quota.invocation(1):
            pytest.fail("Native invocation bypassed occupied workflow slot")
    quota.release(review, "held-by-workflow")
    with quota.invocation(1) as lease:
        lease.ensure_active()
    assert quota.status(ledger)["charged_requests"] == 1


def _contend(path, root, start, results):
    os.environ["HUNTERQA_APPROVED_ROOTS"] = root
    os.environ["HUNTERQA_QUOTA_LEDGER"] = path
    if not start.wait(10):
        results.put("start-timeout")
        return
    try:
        with quota.invocation(3) as lease:
            lease.ensure_active()
        results.put("admitted")
    except PermissionError:
        results.put("denied")


def test_independent_process_invocations_cannot_oversubscribe(ledger, tmp_path):
    with sqlite3.connect(ledger) as db:
        db.execute("UPDATE configuration SET max_requests=5,max_active_runs=8")
    context = multiprocessing.get_context("spawn")
    start, results = context.Event(), context.Queue()
    workers = [context.Process(target=_contend, args=(str(ledger), str(tmp_path), start, results)) for _ in range(4)]
    try:
        for worker in workers:
            worker.start()
        start.set()
        outcomes = [results.get(timeout=15) for _ in workers]
        for worker in workers:
            worker.join(10)
        assert all(worker.exitcode == 0 for worker in workers)
    except queue.Empty:
        pytest.fail("Owned quota contender did not finish")
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(5)
        results.close()
    assert sorted(outcomes) == ["admitted", "denied", "denied", "denied"]
    state = quota.status(ledger)
    assert state["charged_requests"] == 3 and state["active_runs"] == 0


@pytest.mark.parametrize("path", [r"\\server\share\quota.sqlite3", "//server/share/quota.sqlite3"])
def test_unc_ledger_rejected_without_filesystem_lookup(monkeypatch, path):
    monkeypatch.setattr(quota, "_approved_file", lambda *a: pytest.fail("UNC path reached filesystem lookup"))
    monkeypatch.setenv("HUNTERQA_QUOTA_LEDGER", path)
    with pytest.raises(ValueError, match="local filesystem"):
        quota.configured_review()
