"""Bounded TCP connect enumeration of exact profile-admitted URL host/ports."""
from __future__ import annotations

import socket
import time

from .bounty import BountyPolicy
from .engagement import digest, resolve_pinned
from .workflow_network import NetworkJournal


def enumerate_services(request, *, connector=socket.create_connection, sleeper=time.sleep):
    policy = BountyPolicy.from_dict(request["policy"])
    step = request["step"]
    if len(step["targets"]) > step["requests"]:
        raise ValueError("Service targets exceed reservation")
    journal = NetworkJournal(request["network_log"])
    observations = []
    try:
        for index, target in enumerate(step["targets"]):
            if index:
                sleeper(request["interval_seconds"])
            _, host, port, _ = policy.authorize_url(target, "HEAD" if "HEAD" in policy.methods else "GET")
            ip = resolve_pinned(policy, host, port)
            journal.append("intent", target, "TCP")
            try:
                with connector((ip, port), timeout=3):
                    outcome = "connected"
            except ConnectionRefusedError:
                outcome = "refused"
            except TimeoutError:
                outcome = "timeout"
            except OSError:
                outcome = "unreachable"
            journal.append("connect-outcome", target, "TCP", outcome=outcome)
            observations.append({"target_sha256": digest(target), "port": port,
                "transport": "tcp", "outcome": outcome, "verification_status": "unverified"})
        return {"adapter": "service-enumeration", "adapter_version": 1, "requests": len(observations),
            "findings": [], "observations": observations,
            "limitations": ["TCP reachability only; no banners, TLS validation, OS fingerprinting, UDP, AD or attack-path testing",
                "Only exact profile-admitted URL host/ports; no subnet expansion or automatic port ranges"]}
    finally:
        journal.close()
