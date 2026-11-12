"""Typed facade for existing authorized collectors; never an HTTP executor."""
import ipaddress

from .bounty import _approved_file, _decode_json
from .source_files import read_bounded

CONNECTORS = {"azure-inventory": "cloud", "gcp-inventory": "cloud", "gcp-permissions": "cloud",
    "aws-inventory": "cloud", "ad-directory": "ad", "network-service": "network", "web-scenarios": "web"}


def execute(connector, input_file, *, mode, authorized=False, credentials=None, profile=None,
        session_file=None, session_key=None, approval=None):
    if authorized is not True:
        raise PermissionError("Actual collection requires --authorized")
    if connector not in CONNECTORS or mode not in {"LAB", "LIVE"}:
        raise ValueError("Select a supported collector and explicit source mode")
    if CONNECTORS[connector] == "cloud" and mode != "LIVE":
        raise ValueError("External cloud APIs use LIVE intent; provider validation is separate")
    if connector in {"aws-inventory", "ad-directory", "web-scenarios"}:
        if not isinstance(approval, str):
            raise ValueError("The existing collector approval fingerprint is required")
    token_options = {}
    if connector in {"azure-inventory", "gcp-inventory", "gcp-permissions"}:
        if credentials is not None:
            if session_file is not None or session_key is not None:
                raise ValueError("Choose one credential source, not both")
        else:
            if session_file is None or session_key is None:
                raise ValueError("Supply a private token file or encrypted dedicated provider vault")
            from .cloud_inventory_common import token_provider
            token_options["credential_provider"] = token_provider("azure" if connector == "azure-inventory" else "gcp", session_file, session_key)
    if connector in {"aws-inventory", "ad-directory"} and (session_file is None or session_key is None):
        raise ValueError("Supply the existing encrypted dedicated credential vault")
    if connector == "azure-inventory":
        from .azure_inventory import inventory
        return inventory(input_file, credentials, authorized=True, **token_options)
    if connector == "gcp-inventory":
        from .gcp_inventory import inventory
        return inventory(input_file, credentials, authorized=True, **token_options)
    if connector == "gcp-permissions":
        from .gcp_permissions import check_permissions
        return check_permissions(input_file, credentials, authorized=True, **token_options)
    if connector == "aws-inventory":
        from .aws_inventory import inventory
        return inventory(input_file, session_file, session_key, approval, authorized=True)
    if connector == "ad-directory":
        from .ad_directory import contract, collect, analyze
        if contract(input_file, session_file, session_key)[0]["mode"] != mode:
            raise ValueError("Source mode differs from the approved directory contract")
        snapshot, receipt = collect(input_file, session_file, session_key, approval, authorized=True)
        result = analyze(snapshot)
        result.update(snapshot=snapshot, collection=receipt, approval_sha256=receipt["approval_sha256"], stopped=receipt["error_type"] is not None)
        return result
    if connector == "network-service":
        from .service_fingerprints import inspect
        data = _decode_json(read_bounded(_approved_file(input_file), 16384))
        if mode == "LAB" and ipaddress.ip_address(data["server_ip"]).is_global:
            raise ValueError("LAB must use an explicitly approved numeric private endpoint")
        return inspect(input_file, authorized=True)
    from .scenario_assessment import load, run
    if profile is None:
        raise ValueError("Supply the existing scenario profile")
    policy, _, _, _ = load(profile, input_file, session_file=session_file, session_key=session_key)
    if mode == "LAB":
        if not policy.lab_mode or not policy.allow_private_network:
            raise ValueError("LAB scenarios require the existing explicit private-lab scope")
        try:
            if any(ipaddress.ip_address(host).is_global for host in policy.allowed_hosts):
                raise ValueError
        except ValueError:
            raise ValueError("The shared LAB facade accepts numeric private targets only; use the original scoped command for DNS-based laboratory contracts") from None
    return run(profile, input_file, approval, authorized=True, session_file=session_file, session_key=session_key)


def normalized(connector, mode, native, native_sha256):
    """Preserve original results; do not turn a canary/roundtrip into impact proof."""
    from .assessment_modes import envelope, collection_counts
    if connector not in CONNECTORS or mode not in {"LAB", "LIVE"}:
        raise ValueError("Unsupported native collection")
    source = "DEMO" if native.get("synthetic") is True else mode
    result = dict(native)
    result.setdefault("findings", [])
    if connector == "web-scenarios":
        rows = []
        for case in native.get("cases", []):
            observed = case.get("state") == "matched" and case.get("kind") in {"sqli-boolean", "xss-context", "ssrf-callback"}
            timing = case.get("state") == "timing_signal" and case.get("kind") == "sqli-timing"
            different = case.get("state") == "different" and case.get("kind") == "workflow"
            if not (observed or timing or different):
                continue
            cwe = {"sqli-boolean": "CWE-89", "xss-context": "CWE-79", "ssrf-callback": "CWE-918", "sqli-timing": "CWE-89", "workflow": "CWE-840"}[case["kind"]]
            rows.append({"rule_id": "scenario." + case["kind"] + ".review", "test_case": case["id"],
                "title": "Review owned canary observation: " + case["kind"] if observed else "Review timing signal without SQL proof" if timing else "Review workflow contract mismatch",
                "severity": "WARNING" if observed else "INFO", "cwe": cwe, "file_path": "external-evidence", "line_start": 1,
                "remediation": "Inspect the original private controls and target context; independently verify impact before confirming a vulnerability."})
        result["findings"] = rows
    report = envelope(CONNECTORS[connector], source, result, [{"sha256": native_sha256}],
        origin="generated-synthetic" if source == "DEMO" else "operator-supplied-evidence")
    report.update(collector=connector, native_report_sha256=native_sha256, approval_sha256=native.get("approval_sha256"),
        collection={key: value for key, value in native.items() if key not in {"findings", "snapshot"}},
        stopped=native.get("stopped", False))
    return collection_counts(report, native, connector)
