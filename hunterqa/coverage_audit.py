"""Explicit seven-area coverage contract. An adapter is not complete coverage."""
from .workflow_protocol import tool_catalog

AREAS = (
    ("website-discovery", "Website discovery", ["web-discovery"],
     "Bounded unauthenticated HTML links and form inventory",
     ["JavaScript-heavy discovery", "Session-aware crawling", "Comprehensive endpoint discovery"]),
    ("active-vulnerability-testing", "Active vulnerability testing", ["web-canary-check"],
     "Fixed inert markup and SQL error comparisons, with baseline controls",
     ["Confirmed SQLi/XSS validators", "SSRF", "File upload", "Traversal", "Blind/OOB and application-specific validation"]),
    ("authentication-authorization", "Authentication and authorization", ["authorization-matrix"],
     "Explicit dedicated-role/anonymous GET contracts and isolated Authorization headers",
     ["SSO negotiation", "Complex session handling", "Stateful business logic", "General tenant-boundary discovery"]),
    ("network-infrastructure", "Network and infrastructure", ["service-enumeration", "service-evidence"],
     "Exact admitted TCP host/port reachability and service-evidence import",
     ["OS fingerprinting", "Broad service/version assessment", "Active Directory", "Internal attack-path testing", "UDP"]),
    ("cloud-runtime", "Cloud runtime", ["aws-account-audit", "source-review"],
     "Fixed AWS identity/account-summary APIs and selected local configuration patterns",
     ["Resource and effective-permission inventory", "Azure/GCP runtime adapters", "Cloud infrastructure assessment"]),
    ("production-hardening", "Production platform hardening", [],
     "Local supervised workers, per-run controls and optional shared host-local quota ledger",
     ["Authenticated multi-user RBAC", "Independently verified owner grants", "OS sandbox", "Distributed workers", "Enforced cross-host organization quotas"]),
    ("detection-effectiveness", "Demonstrated detection effectiveness", [],
     "Versioned owned application benchmark, labeled positive/negative cues and retained evidence",
     ["Independent real-world evaluation", "Representative per-class false-negative rates", "Complete standards coverage"]),
)


def coverage_audit():
    catalog = {row["id"]: row for row in tool_catalog()}
    return {"engine": "hunterqa_coverage_audit", "schema_version": 1,
        "all_seven_areas_complete": False,
        "areas": [{"id": key, "name": name, "status": "partial", "implemented": implemented,
            "adapters": [catalog[tool] for tool in tools], "missing": missing}
            for key, name, tools, implemented, missing in AREAS],
        "verification": "Implementation inventory, not a runtime scan or proof of effectiveness; run owned benchmarks and review their limits",
        "authorization": "Local operator attestations do not independently verify target-owner consent"}
