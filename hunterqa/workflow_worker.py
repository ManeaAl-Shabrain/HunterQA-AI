"""Fixed trusted worker; no arbitrary commands, imports or target execution.

Invoked by absolute path with Python isolated mode. It is process isolation,
not a container or an operating-system filesystem/network sandbox.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

# Only the installed trusted package location is added, never the target tree.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hunterqa.bounty import BountyPolicy, _read_json  # noqa: E402
from hunterqa.engagement import _expiry, digest, pinned_request, utcnow  # noqa: E402
from hunterqa.engines.config_audit import audit_project  # noqa: E402
from hunterqa.engines.dependencies import inventory  # noqa: E402
from hunterqa.engines.openapi import audit_openapi  # noqa: E402
from hunterqa.external_evidence import import_external  # noqa: E402
from hunterqa.workflow_store import approved_directory, private_write  # noqa: E402
from hunterqa.workflow_network import NetworkJournal  # noqa: E402

ADAPTERS = {"declared-assets", "service-evidence", "source-review", "external-findings",
            "approved-observation", "evidence-index", "report-draft"}


def _start_supervisor(request):
    """Worker independently stops after parent death, expiry, deadline or STOP."""
    close = lambda: None
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel.OpenProcess(0x00100000, False, request["parent_pid"])
        parent_alive = lambda: bool(handle) and kernel.WaitForSingleObject(handle, 0) == 258
        close = lambda: kernel.CloseHandle(handle) if handle else None
    else:
        parent_alive = lambda: os.getppid() == request["parent_pid"]
    deadline = time.monotonic() + request["watchdog_seconds"]
    stop = Path(request["stop_path"])
    done = threading.Event()

    def check():
        return (parent_alive() and not stop.exists() and time.monotonic() < deadline
                and utcnow() < _expiry(request["expires_at"]))

    if not check():
        os._exit(124)

    def supervise():
        while not done.wait(0.1):
            if not check():
                os._exit(124)

    thread = threading.Thread(target=supervise, daemon=True)
    thread.start()

    def finish():
        done.set()
        thread.join(1)
        close()

    return finish


def execute(request):
    step, binding = request["step"], request["binding"]
    tool = step["tool"]
    if tool not in ADAPTERS:
        raise ValueError("Unsupported fixed adapter")
    result = {"adapter": tool, "adapter_version": 1, "findings": [], "observations": [],
              "requests": 0, "verification_status": "unverified"}
    if tool == "declared-assets":
        assets = []
        for target in step["targets"]:
            parts = urlsplit(target)
            assets.append({"url": target, "host": parts.hostname,
                           "port": parts.port or (443 if parts.scheme == "https" else 80),
                           "provenance": "operator-declared", "live_verified": False})
        result["assets"] = assets
    elif tool == "source-review":
        root = approved_directory(binding["project"])
        findings = audit_project(root) + audit_openapi(root)
        for row in findings:
            row.pop("code", None)
            row["verification_status"] = "unverified"
        result.update(findings=findings[:1000], dependencies=inventory(root)[:2000])
    elif tool == "service-evidence":
        data = _read_json(binding["file"], 2_000_000)
        rows = data.get("services") if isinstance(data, dict) else None
        if not isinstance(rows, list) or len(rows) > 500:
            raise ValueError("Expected at most 500 service evidence entries")
        services = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"url", "service"}:
                raise ValueError("Invalid service evidence fields")
            if row["url"] not in step["targets"] or row["service"] not in ("http", "https"):
                raise ValueError("Service evidence is outside declared step scope")
            if row["service"] != urlsplit(row["url"]).scheme:
                raise ValueError("Service scheme assertion contradicts the declared endpoint")
            services.append({"url": row["url"], "service": row["service"],
                             "provenance": "imported-assertion", "live_verified": False})
        result["services"] = services
    elif tool == "external-findings":
        imported = import_external(request["profile_path"], binding["file"], binding["tool"], authorized=True)
        # Profile scope can be wider than this step: enforce exact step endpoints.
        allowed = {hashlib.sha256(url.encode()).hexdigest() for url in step["targets"]}
        result["findings"] = [row for row in imported["findings"] if row["target_ref_hash"] in allowed]
        result["import_summary"] = imported["summary"]
    elif tool == "approved-observation":
        policy = BountyPolicy.from_dict(request["policy"])
        method = "HEAD" if "HEAD" in policy.methods else "GET"
        journal = NetworkJournal(request["network_log"])
        try:
            for index, target in enumerate(step["targets"]):
                if index:
                    time.sleep(request["interval_seconds"])
                journal.append("intent", target, method)
                try:
                    response = pinned_request(policy, target, method)
                except Exception as exc:
                    journal.append("error", target, method, error_type=type(exc).__name__)
                    raise
                result["requests"] += 1
                status = response["status"]
                journal.append("response", target, method, status=status)
                result["observations"].append({"target_sha256": digest(target), "status": status,
                                               "method": method,
                                               "body_sha256": hashlib.sha256(response["body"]).hexdigest(),
                                               "verification_status": "unverified"})
                if status in (401, 403, 429) or status >= 500 or 300 <= status < 400:
                    result["safety_stop"] = True
                    break
        finally:
            journal.close()
    elif tool in ("evidence-index", "report-draft"):
        result["dependency_evidence"] = request["dependency_evidence"]
        result["purpose"] = "fingerprint-index" if tool == "evidence-index" else "report-inputs"
    return result


def main():
    if len(sys.argv) != 3:
        raise ValueError("Fixed request/output arguments required")
    request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if sys.platform.startswith("linux"):
        import resource
        for key, ceiling in ((resource.RLIMIT_CPU, request["step"]["timeout_seconds"] + 1),
                             (resource.RLIMIT_AS, 512 * 1024 * 1024), (resource.RLIMIT_NOFILE, 128)):
            _, hard = resource.getrlimit(key)
            ceiling = min(ceiling, hard) if hard != resource.RLIM_INFINITY else ceiling
            resource.setrlimit(key, (ceiling, ceiling))
    finish = _start_supervisor(request)
    try:
        result = execute(request)
        private_write(Path(sys.argv[2]), result)
    finally:
        finish()


if __name__ == "__main__":
    main()
