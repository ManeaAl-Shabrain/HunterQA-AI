"""Actual owned collectors and unchanged delegates under the shared facade."""
import json
import socketserver
import threading
from datetime import timedelta

import pytest

from hunterqa import assessment_collect as collect, assessment_modes as modes, scenario_lab, scenario_assessment
from hunterqa.cli import main
from hunterqa.engagement import utcnow


@pytest.fixture
def approved(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    monkeypatch.delenv("HUNTERQA_QUOTA_LEDGER", raising=False)
    return tmp_path


def test_real_owned_service_collected_and_original_report_preserved(approved):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            assert self.request.recv(32) == b"PING\r\n"
            self.request.sendall(b"+PONG\r\n")
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        source = approved / "network.json"
        source.write_text(json.dumps({"schema_version": 1, "protocol": "redis", "authorization_reference": "Owned loopback fixture",
            "acknowledged_authorization": True, "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(),
            "server_ip": "127.0.0.1", "server_port": server.server_address[1], "allow_private_network": True}))
        native, output = approved / "native.json", approved / "report.json"
        main(["assessment-collect", "--connector", "network-service", "--mode", "LAB", "--input", str(source),
            "--native-out", str(native), "--out", str(output), "--authorized"])
        report = modes.load_report(output)
        assert report["execution_source"] == "LAB" and report["collector"] == "network-service"
        assert report["collection"]["outcome"] == "observed" and not report["collection"]["product_verified"]
        assert report["network_operations"]["tcp_connections_attempted"] == 1 and report["network_requests"] == 0
        assert json.loads(native.read_text())["engine"] == "scoped-service-fingerprint"
        assert report["evidence"] and not report["real_provider_verified"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_real_owned_web_contract_reuses_approval_and_does_not_turn_safe_contract_into_vulnerability(approved):
    with scenario_lab.serve() as lab:
        profile, plan = approved / "profile.json", approved / "plan.json"
        profile.write_text(json.dumps(scenario_lab.profile(lab)))
        case = {"id": "anonymous-denied", "kind": "workflow", "owned_test_endpoint": True, "steps": [{
            "url": lab["base"] + "/resource", "method": "GET", "actor": "anonymous", "query": None,
            "form": None, "expected_status": 403, "expected_body_sha256": None}]}
        plan.write_text(json.dumps(scenario_lab.plan([case])))
        approval = scenario_assessment.preflight(profile, plan)["approval_sha256"]
        native = collect.execute("web-scenarios", plan, mode="LAB", profile=profile, approval=approval, authorized=True)
        assert native["requests"] == 1 and native["cases"][0]["state"] == "matched"
        report = collect.normalized("web-scenarios", "LAB", native, "1" * 64)
        assert not report["findings"] and report["execution_source"] == "LAB"
        assert report["network_requests"] == 1
        assert ("GET", "/resource") in lab["requests"]
        with pytest.raises(PermissionError):
            collect.execute("web-scenarios", plan, mode="LAB", profile=profile, approval="0" * 64, authorized=True)


def test_cloud_delegate_uses_existing_contract_and_does_not_bypass_source_or_authorization(approved, monkeypatch):
    from hunterqa import azure_inventory
    calls = []
    def native(path, credential, *, authorized):
        calls.append((path, credential, authorized))
        return {"engine": "azure-test-fixture", "findings": [], "synthetic": True}
    monkeypatch.setattr(azure_inventory, "inventory", native)
    with pytest.raises(PermissionError):
        collect.execute("azure-inventory", "missing", mode="LIVE")
    with pytest.raises(ValueError):
        collect.execute("azure-inventory", "missing", mode="LAB", credentials="private", authorized=True)
    assert not calls
    result = collect.execute("azure-inventory", "contract", mode="LIVE", credentials="private", authorized=True)
    assert calls == [("contract", "private", True)]
    report = collect.normalized("azure-inventory", "LIVE", result, "1" * 64)
    assert report["synthetic"] and report["execution_source"] == "DEMO" and not report["real_provider_verified"]


def test_upload_success_and_timing_signals_are_not_promoted_to_confirmed_impact():
    native = {"engine": "approved-scenario-suite", "cases": [
        {"id": "upload", "kind": "upload-canary", "state": "matched"},
        {"id": "timing", "kind": "sqli-timing", "state": "timing_signal"}]}
    report = collect.normalized("web-scenarios", "LAB", native, "1" * 64)
    assert len(report["findings"]) == 1 and report["findings"][0]["severity"] == "INFO"
    assert report["findings"][0]["verification_status"] == "unverified"


@pytest.mark.parametrize("input_mode,data", [("aws-iam", {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
    ("gcp-iam", {"bindings": [{"role": "roles/owner", "members": ["user:owned@example.test"]}]}),
    ("azure-nsg", {"properties": {"securityRules": [{"properties": {"access": "Allow", "direction": "Inbound", "protocol": "Tcp", "priority": 200,
        "sourceAddressPrefix": "Internet", "destinationPortRange": "22"}}]}})])
def test_native_cloud_policy_exports_share_existing_detectors_and_provenance(approved, input_mode, data):
    path = approved / "policy.json"
    path.write_text(json.dumps(data))
    original = path.read_bytes()
    report = modes.analyze("cloud", path, mode="LIVE", input_mode=input_mode, authorized=True)
    assert report["findings"] and report["execution_source"] == "LIVE" and not report["real_provider_verified"]
    assert path.read_bytes() == original
    assert all(row["evidence_ids"] for row in report["findings"])


def test_cross_module_correlation_preserves_mixed_demo_lab_provenance(approved):
    from hunterqa.assessment_correlation import correlate
    paths = []
    for module, mode, origin in (("cloud", "DEMO", "generated-synthetic"), ("iam", "LAB", "operator-supplied-evidence")):
        report = modes.envelope(module, mode, {"findings": []}, [{"sha256": "1" * 64}], origin=origin)
        path = approved / (module + ".json")
        path.write_text(json.dumps(report))
        paths.append(path)
    report = correlate(paths, authorized=True)
    assert report["mixed_execution_sources"] and report["links"]
    assert {row["execution_source"] for row in report["sources"]} == {"DEMO", "LAB"}
    assert not report["customer_vulnerabilities_confirmed"]
