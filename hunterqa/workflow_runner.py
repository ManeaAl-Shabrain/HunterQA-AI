"""Single-coordinator, supervised fixed-adapter execution with durable quotas.

No automatic restart of interrupted work; a new reviewed run is required.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from importlib.metadata import PackageNotFoundError, version as distribution_version
from pathlib import Path

from .bounty import _approved_file, _read_json
from .engagement import _expiry, _policy_snapshot, digest, utcnow
from .source_files import read_bounded
from .workflow_protocol import CATALOG, compile_protocol, _fields
from .workflow_store import Store, approved_directory, private_write, run_lock
from .workflow_worker import ADAPTERS
from .workflow_network import inspect_network, journal_targets, journal_queries
from . import shared_quota


def _runtime_identity():
    root = Path(__file__).resolve().parent
    try:
        package_version = distribution_version("hunterqa-ai")
    except PackageNotFoundError:
        package_version = "uninstalled-source"
    components = {}
    for name in ("botocore", "defusedxml"):
        try:
            components[name] = distribution_version(name)
        except PackageNotFoundError:
            components[name] = None
    fingerprints = {str(path.relative_to(root)).replace("\\", "/"):
                    hashlib.sha256(read_bounded(path, 2_000_000)).hexdigest()
                    for path in sorted(root.rglob("*.py")) if not path.is_symlink()}
    return digest({"python": sys.version, "distribution_version": package_version,
                   "optional_cloud_components": components,
                   "package_sources": fingerprints})


def execution_plan(profile, protocol, bindings, *, now=None):
    preflight = compile_protocol(profile, protocol, now=now)
    data = _read_json(protocol, 65_536)
    if digest(data) != preflight["protocol_sha256"]:
        raise ValueError("Protocol changed during preflight")
    binding_data = _read_json(bindings, 65_536)
    _fields(binding_data, ("schema_version", "steps"), "bindings")
    if type(binding_data["schema_version"]) is not int or binding_data["schema_version"] != 1:
        raise ValueError("Unsupported bindings schema")
    if not isinstance(binding_data["steps"], dict):
        raise ValueError("Binding steps must be an object")
    ids = {step["id"] for step in data["steps"]}
    if set(binding_data["steps"]) != ids:
        raise ValueError("Provide one explicit binding object for every step")
    normalized, input_bytes, request_contracts = {}, 0, {}
    for step in data["steps"]:
        tool, step_id = step["tool"], step["id"]
        if tool not in ADAPTERS:
            raise ValueError("Adapter is planning-only and unavailable to the runner")
        dispatches = step["requests"] if tool in ("web-discovery", "authorization-matrix", "web-canary-check") else len(step["targets"])
        if CATALOG[tool][1] and ((dispatches - 1) * data["limits"]["interval_seconds"] >= step["timeout_seconds"]):
            raise ValueError("Step timeout cannot accommodate target spacing; split this step")
        value = binding_data["steps"][step_id]
        fields = {"source-review": ("project",), "service-evidence": ("file",),
                  "authorization-matrix": ("file", "secret_file"),
                  "web-canary-check": ("file",),
                  "aws-account-audit": ("file", "secret_file"),
                  "web-discovery": ("max_depth",),
                  "external-findings": ("file", "tool")}.get(tool, ())
        _fields(value, fields, "adapter binding")
        if tool == "web-discovery":
            from .workflow_protocol import _integer
            _integer(value["max_depth"], 0, 3, "max_depth")
        for field in ("project", "file", "secret_file"):
            if field in value and (not isinstance(value[field], str) or not 1 <= len(value[field]) <= 4096):
                raise ValueError("Binding paths must be bounded strings")
        normalized[step_id] = dict(value)
        if tool == "external-findings" and value["tool"] not in ("nuclei", "zap"):
            raise ValueError("Supported imported formats are nuclei and zap")
        if "project" in value:
            normalized[step_id]["project"] = str(approved_directory(value["project"]))
        if "file" in value:
            path = _approved_file(value["file"])
            raw = read_bounded(path, 2_000_000)
            input_bytes += len(raw)
            if input_bytes > 16_000_000:
                raise ValueError("Aggregate bound input exceeds 16 MB")
            normalized[step_id].update(file=str(path), file_sha256=hashlib.sha256(raw).hexdigest())
        if "secret_file" in value:
            path = _approved_file(value["secret_file"])
            raw = read_bounded(path, 32_768)
            normalized[step_id].update(secret_file=str(path), secret_file_sha256=hashlib.sha256(raw).hexdigest())
        if tool == "authorization-matrix":
            from .access_matrix import validate_matrix, credentials
            matrix = validate_matrix(_read_json(value["file"], 65_536), _policy_snapshot(profile)[0])
            if len(matrix["cases"]) > step["requests"] or not {c["url"] for c in matrix["cases"]} <= set(step["targets"]):
                raise ValueError("Access cases exceed step reservation or targets")
            credentials(normalized[step_id], matrix["roles"])
        if tool == "web-canary-check":
            from .web_canaries import validate_canaries, variants
            manifest = validate_canaries(_read_json(value["file"], 65_536), _policy_snapshot(profile)[0])
            if 2 * len(manifest["checks"]) > step["requests"] or not {c["url"] for c in manifest["checks"]} <= set(step["targets"]):
                raise ValueError("Canary checks exceed step reservation or targets")
            request_contracts[step_id] = [{"case": check["id"], "url": check["url"], "method": "GET",
                "variant": variant, "query": query} for check in manifest["checks"] for variant, query in variants(check)]
        if tool == "aws-account-audit":
            from .cloud_account import TARGETS, validate_account, credentials, require_cloud
            require_cloud()
            validate_account(_read_json(value["file"], 1024))
            credentials(normalized[step_id])
            if step["targets"] != TARGETS or step["requests"] != 2:
                raise ValueError("AWS checks require exactly the two fixed endpoints and two requests")
    review = {"protocol_sha256": preflight["protocol_sha256"],
              "policy_sha256": preflight["policy_sha256"], "bindings": normalized,
              "runtime_sha256": _runtime_identity(),
              "shared_quota": shared_quota.configured_review(),
              "request_contracts": request_contracts,
              "adapter_contract": "hunterqa-fixed-workers-v1"}
    return {"engine": "hunterqa_execution_plan", "execution_sha256": digest(review),
            "review": review, "preflight": preflight,
            "local_operator_attestation_only": True,
            "source_snapshot": "Project bindings approve a mutable local directory, not immutable source bytes",
            "isolation": "Trusted Python worker processes; not an OS sandbox"}


def _environment():
    # Do not pass test credentials, cloud keys, proxy configuration or model tokens.
    names = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL")
    env = {name: os.environ[name] for name in names if name in os.environ}
    env["HUNTERQA_APPROVED_ROOTS"] = os.environ.get("HUNTERQA_APPROVED_ROOTS", "")
    return env


def _terminate(process):
    # Fixed workers cannot spawn tools/children; kill the worker even in DNS/read.
    if process.poll() is None:
        process.kill()
    process.wait(timeout=10)


def run_workflow(profile, protocol, bindings, out_dir, *, execution_approval,
                 protocol_approval=None, approved_steps=(), authorized=False,
                 poll_interval=0.05, operator="local-operator"):
    if not authorized:
        raise PermissionError("Workflow execution requires --authorized")
    if not isinstance(operator, str) or not 1 <= len(operator) <= 200 or any(ord(c) < 32 for c in operator):
        raise ValueError("Operator must be bounded single-line text")
    plan = execution_plan(profile, protocol, bindings)
    if execution_approval != plan["execution_sha256"]:
        raise PermissionError("Approve the exact workflow-run-plan execution fingerprint")
    checked = compile_protocol(profile, protocol, approved_steps=approved_steps,
                               approved_fingerprint=protocol_approval, authorized=authorized)
    if checked["pending_checkpoints"]:
        raise PermissionError("Every checkpoint requires an explicit step review")
    if checked["protocol_sha256"] != plan["review"]["protocol_sha256"] or not checked["window_open"]:
        raise PermissionError("Workflow changed or testing window is not open")
    raw_profile = read_bounded(_approved_file(profile), 32_768)
    if hashlib.sha256(raw_profile).hexdigest() != checked["policy_sha256"]:
        raise ValueError("Profile changed during run preparation")
    data = _read_json(protocol, 65_536)
    if digest(data) != checked["protocol_sha256"]:
        raise ValueError("Protocol changed during run preparation")
    destination = Path(out_dir).expanduser().absolute()
    parent = approved_directory(destination.parent)
    # Keep generated run artifacts out of every reviewed source tree.
    for binding in plan["review"]["bindings"].values():
        if "project" in binding and destination.is_relative_to(Path(binding["project"])):
            raise ValueError("Run directory must be outside reviewed source trees")
    destination = parent / destination.name
    run_id = uuid.uuid4().hex
    quota = plan["review"]["shared_quota"]
    reserved = False
    store = None
    try:
        if destination.exists():
            raise FileExistsError("A workflow run is create-only")
        if quota:
            shared_quota.reserve(quota, run_id, checked["reserved_requests"])
            reserved = True
        destination.mkdir(mode=0o700)  # Never silently resume/replay.
        with run_lock(destination):
            store = Store(destination, create=True)
            store.meta("run_id", run_id)
            store.meta("execution", plan)
            store.meta("status", "running")
            store.meta("created_at", utcnow().isoformat())
            store.meta("operator", operator)
            store.meta("stop_file", data["stop_file"])
            store.meta("charged_requests", 0)
            private_write(destination / "protocol.json", data)
            # Snapshot input reports so later edits cannot change worker evidence.
            bindings_snapshot = plan["review"]["bindings"]
            for step_id, binding in bindings_snapshot.items():
                if "file" in binding:
                    raw = read_bounded(_approved_file(binding["file"]), 2_000_000)
                    if hashlib.sha256(raw).hexdigest() != binding["file_sha256"]:
                        raise ValueError("Bound input changed after execution review")
                    input_path = destination / f"{step_id}.input"
                    fd = os.open(input_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(raw)
                    binding["file"] = str(input_path)
            profile_copy = destination / "profile.json"
            fd = os.open(profile_copy, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw_profile)
            with store.db:
                store.db.executemany("INSERT INTO steps VALUES (?, ?, 'pending', NULL, NULL)",
                                     [(step["id"], step["tool"]) for step in data["steps"]])
            store.event("run-start", execution_sha256=plan["execution_sha256"],
                        operator=operator,
                        reviewed_checkpoints=checked["reviewed_checkpoints"],
                        authorization_kind="local-operator-attestation")
            _coordinate(store, data, bindings_snapshot, profile_copy, profile, protocol,
                        poll_interval=poll_interval)
            from .workflow_results import summarize_run
            result = summarize_run(destination, store=store)
            private_write(destination / "summary.json", result)
            from .workflow_results import export_report
            export_report(destination, destination / "report.html", "html")
            export_report(destination, destination / "report.sarif", "sarif")
            return result
    except BaseException:
        if store:
            for step in store.steps():
                if step["state"] in ("running", "pending"):
                    store.state(step["id"], "cancelled", error="coordinator-interrupted")
            store.audited_meta("status", "interrupted", "run-interrupted")
        raise
    finally:
        if store:
            store.close()
        if reserved:
            shared_quota.release(quota, run_id)


def _coordinate(store, protocol, bindings, profile_copy, original_profile, original_protocol,
                *, poll_interval):
    by_id = {step["id"]: step for step in protocol["steps"]}
    limits = protocol["limits"]
    deadline = time.monotonic() + limits["timeout_seconds"]
    stop = store.run / protocol["stop_file"]
    active, finished = {}, set()
    halted = None
    charged, next_network = 0, 0.0
    worker = Path(__file__).with_name("workflow_worker.py").resolve()
    batches = store.meta("execution")["preflight"]["planning_batches"]
    sequence = [step_id for batch in batches for step_id in batch]
    quota = store.meta("execution")["review"].get("shared_quota")

    def record_network(step_id):
        step = by_id[step_id]
        kwargs = {}
        if step["tool"] == "web-discovery":
            kwargs = {"discovery_policy": _policy_snapshot(profile_copy)[0], "request_budget": step["requests"]}
        elif step["tool"] == "service-enumeration":
            kwargs = {"transport": "tcp"}
        elif step["tool"] == "aws-account-audit":
            kwargs = {"transport": "aws-query"}
        journal = inspect_network(store.run / f"{step_id}.network.jsonl", journal_targets(step, bindings[step_id]),
                                  request_digests=journal_queries(step, bindings[step_id]), **kwargs)
        store.event("network-evidence", step=step_id, **{key: value for key, value in journal.items() if key != "records"})

    try:
        while len(finished) < len(by_id):
            now = time.monotonic()
            _, current_profile_hash = _policy_snapshot(original_profile)
            if (current_profile_hash != protocol["policy_sha256"]
                    or digest(_read_json(original_protocol, 65_536)) != digest(protocol)):
                halted = "authorization-changed"
            if stop.exists():
                halted = "emergency-stop"
            elif quota and not shared_quota.check(quota, store.meta("run_id")):
                halted = "shared-quota-stopped-or-changed"
            elif now >= deadline:
                halted = "run-timeout"
            elif utcnow() >= _expiry(protocol["expires_at"]):
                halted = "authorization-expired"
            if halted:
                for step_id, item in list(active.items()):
                    _terminate(item["process"])
                    if item["network"]:
                        record_network(step_id)
                    store.state(step_id, "cancelled", error=halted)
                    finished.add(step_id)
                    del active[step_id]
                for step_id in sequence:
                    if step_id not in finished:
                        store.state(step_id, "blocked", error=halted)
                        finished.add(step_id)
                break
            for step_id, item in list(active.items()):
                process = item["process"]
                timed_out = now >= item["deadline"]
                if timed_out or process.poll() is not None:
                    if timed_out:
                        _terminate(process)
                        store.state(step_id, "failed", error="step-timeout")
                    elif process.returncode != 0:
                        store.state(step_id, "failed", error="worker-exit")
                    else:
                        result = _read_json(item["output"], 2_000_000)
                        if not isinstance(result, dict) or result.get("adapter") != by_id[step_id]["tool"]:
                            raise ValueError("Worker output contract mismatch")
                        status = "stopped" if result.get("safety_stop") else "succeeded"
                        store.state(step_id, status, result=result)
                        if status == "stopped":
                            halted = "network-safety-stop"
                    if item["network"]:
                        record_network(step_id)
                        if timed_out or process.returncode != 0:
                            halted = "network-worker-failed"
                        next_network = time.monotonic() + limits["interval_seconds"]
                    finished.add(step_id)
                    del active[step_id]
            if halted:
                continue
            states = {row["id"]: row["state"] for row in store.steps()}
            for batch in batches:
                if all(step_id in finished for step_id in batch):
                    continue
                for step_id in batch:
                    if step_id in finished or step_id in active or len(active) >= limits["concurrency"]:
                        continue
                    step = by_id[step_id]
                    if "project" in bindings[step_id]:
                        approved_directory(bindings[step_id]["project"])
                    dependencies = step["depends_on"]
                    if any(states[parent] in ("failed", "blocked", "stopped", "cancelled") for parent in dependencies):
                        store.state(step_id, "blocked", error="dependency-failed")
                        finished.add(step_id)
                        continue
                    if not all(states[parent] == "succeeded" for parent in dependencies):
                        continue
                    network = CATALOG[step["tool"]][1]
                    if network and (time.monotonic() < next_network or any(x["network"] for x in active.values())):
                        continue
                    if _runtime_identity() != store.meta("execution")["review"]["runtime_sha256"]:
                        halted = "adapter-code-changed"
                        break
                    # Recheck unchanged authorization immediately before dispatch.
                    _, profile_hash = _policy_snapshot(original_profile)
                    if profile_hash != protocol["policy_sha256"] or digest(_read_json(original_protocol, 65_536)) != digest(protocol):
                        halted = "authorization-changed"
                        break
                    if network:
                        if charged + step["requests"] > limits["max_requests"]:
                            halted = "request-budget-exhausted"
                            break
                        charged += step["requests"]
                        store.audited_meta("charged_requests", charged, "quota-reserved",
                                           step=step_id, requests=step["requests"], total=charged)
                    request = {"step": step, "binding": bindings[step_id],
                               "network_log": str(store.run / f"{step_id}.network.jsonl"),
                               "parent_pid": os.getpid(), "stop_path": str(stop),
                               "expires_at": protocol["expires_at"],
                               "watchdog_seconds": min(step["timeout_seconds"], max(0, deadline - time.monotonic())),
                               "profile_path": str(profile_copy),
                               "policy": json.loads(profile_copy.read_text(encoding="utf-8")),
                               "interval_seconds": limits["interval_seconds"],
                               "dependency_evidence": [{"step": parent, "sha256": digest(json.loads(
                                   next(row["result"] for row in store.steps() if row["id"] == parent)))}
                                   for parent in dependencies]}
                    request_path, output = store.run / f"{step_id}.request.json", store.run / f"{step_id}.result.json"
                    private_write(request_path, request)
                    store.state(step_id, "running")
                    process = subprocess.Popen([sys.executable, "-I", "-B", str(worker),
                                                str(request_path), str(output)], cwd=str(store.run),
                                               env=_environment(), stdin=subprocess.DEVNULL,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                               shell=False)
                    active[step_id] = {"process": process, "output": output, "network": network,
                                       "deadline": min(deadline, time.monotonic() + step["timeout_seconds"])}
                break
            if not active and not halted and len(finished) == len(by_id):
                break
            time.sleep(poll_interval)
        states = [row["state"] for row in store.steps()]
        status = "cancelled" if halted else "completed" if all(x == "succeeded" for x in states) else "failed"
        store.audited_meta("status", status, "run-finished", status=status, reason=halted, charged_requests=charged)
    finally:
        for item in active.values():
            _terminate(item["process"])


def stop_run(run):
    store = Store(run, readonly=True)
    try:
        name = store.meta("stop_file")
        from .workflow_protocol import ID
        if not isinstance(name, str) or not ID.fullmatch(name):
            raise ValueError("Invalid stored stop-file name")
        path = store.run / name
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return {"stop_requested": True, "already_requested": True}
        os.close(fd)
        return {"stop_requested": True, "in_flight_workers": "coordinator will terminate workers"}
    finally:
        store.close()


def abandon_run(run, *, authorized=False):
    """Reconcile after a coordinator crash; never relaunch a worker or request."""
    if not authorized:
        raise PermissionError("Abandon requires --authorized")
    with run_lock(run):
        store = Store(run)
        try:
            store.verify()
            if store.meta("status") not in ("running", "interrupted"):
                raise ValueError("Only an interrupted/abandoned coordinator can be reconciled")
            # Signal any surviving trusted worker's independent watchdog first.
            stop_run(run)
            for step in store.steps():
                if step["state"] in ("pending", "running"):
                    store.state(step["id"], "cancelled", error="abandoned-coordinator")
            store.audited_meta("status", "abandoned", "run-abandoned", automatic_replay=False)
        finally:
            store.close()
    return {"status": "abandoned", "execution_resumed": False}


def setup_workflow(profile, project, targets, out_dir, *, observe=False, authorized=False):
    """Create a reviewed-input starter; never starts execution."""
    from datetime import timedelta
    if not authorized:
        raise PermissionError("Workflow setup requires --authorized")
    root = approved_directory(project)
    policy, fingerprint = _policy_snapshot(profile)
    method = "HEAD" if "HEAD" in policy.methods else "GET"
    if not isinstance(targets, list) or not 1 <= len(targets) <= 40 or len(set(targets)) != len(targets):
        raise ValueError("Provide unique exact targets")
    for target in targets:
        policy.authorize_url(target, method)
    if observe and len(targets) > policy.max_requests:
        raise ValueError("Targets exceed the profile request budget")
    destination = Path(out_dir).expanduser().absolute()
    approved_directory(destination.parent)
    if destination.is_relative_to(root):
        raise ValueError("Configuration directory must be outside the reviewed source tree")
    tools = [("assets", "declared-assets"), ("identify", "source-review")]
    if observe:
        tools.append(("validate", "approved-observation"))
    tools += [("evidence", "evidence-index"), ("report", "report-draft")]
    steps, bindings = [], {}
    for index, (step_id, tool) in enumerate(tools):
        active = CATALOG[tool][1]
        steps.append({"id": step_id, "tool": tool,
                      "depends_on": [tools[index - 1][0]] if index else [],
                      "targets": targets, "requests": len(targets) if active else 0,
                      "timeout_seconds": 120 if active else 30, "approval_required": active})
        bindings[step_id] = {"project": str(root)} if tool == "source-review" else {}
    reservation = sum(step["timeout_seconds"] for step in steps)
    reservation += int(max(0, len(targets) - 1) * policy.interval_seconds) + 1 if observe else 0
    now = utcnow()
    data = {"schema_version": 1, "policy_sha256": fingerprint,
            "authorization_reference": policy.authorization_reference,
            "starts_at": now.isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
            "targets": targets, "limits": {"max_requests": len(targets) if observe else 0,
                "interval_seconds": policy.interval_seconds, "concurrency": 1, "timeout_seconds": reservation + 60},
            "stop_file": "emergency-stop", "steps": steps}
    destination.mkdir(mode=0o700)
    private_write(destination / "protocol.json", data)
    private_write(destination / "bindings.json", {"schema_version": 1, "steps": bindings})
    review = execution_plan(profile, destination / "protocol.json", destination / "bindings.json")
    private_write(destination / "execution-plan.json", review)
    return review
