"""Explicit seven-area coverage contract. An adapter is not complete coverage."""
from .workflow_protocol import tool_catalog
from .web_review import catalog as web_review_catalog
from .identity_review import catalog as identity_review_catalog

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
     "Local supervised workers, per-run controls, optional shared quotas and authenticated local dashboard roles",
     ["Hosted multi-user deployment and tenant isolation", "Independently verified owner grants", "OS sandbox", "Distributed workers", "Enforced cross-host organization quotas"]),
    ("detection-effectiveness", "Demonstrated detection effectiveness", [],
     "Versioned owned application benchmark, labeled positive/negative cues and retained evidence",
     ["Independent real-world evaluation", "Representative per-class false-negative rates", "Complete standards coverage"]),
)

FEATURES = {
    "website-discovery": [("Bounded automatic HTML crawling", "web-discovery"), ("Form inventory without submission", "web-discovery")],
    "active-vulnerability-testing": [("Fixed inert-markup baseline/probe comparisons", "web-canary-check"), ("Fixed SQL-error baseline/probe comparisons", "web-canary-check")],
    "authentication-authorization": [("Dedicated-role and anonymous GET contracts", "authorization-matrix"), ("Origin-bound per-request credentials and optional body-hash checks", "authorization-matrix")],
    "network-infrastructure": [("Exact admitted TCP host/port reachability", "service-enumeration"), ("Scoped service-evidence import", "service-evidence")],
    "cloud-runtime": [("Optional read-only AWS identity and account-summary adapter", "aws-account-audit"), ("Selected local configuration/dependency patterns", "source-review")],
    "production-hardening": [("Per-run budgets, approvals, deadlines and emergency stop", None), ("Optional shared host-local quota ledger and crash-slot reconciliation", None), ("Opt-in authenticated local dashboard roles and revocable sessions", None)],
    "detection-effectiveness": [("Versioned owned application cases with positive/negative controls", None), ("Retained run evidence, per-class metrics and current-runtime consistency checks", None)],
}


def coverage_audit():
    catalog = {row["id"]: row for row in tool_catalog()}
    return {"engine": "hunterqa_coverage_audit", "schema_version": 1,
        "all_seven_areas_complete": False,
        "category_packs": [{"name": "Web Application", "skills": web_review_catalog(),
            "all_skills_automated": False, "mode": "offline Python source cues and guided review"},
            {"name": "Auth & Identity", "skills": identity_review_catalog(),
             "all_skills_automated": False, "mode": "offline JWT samples and declared web-client configuration"}],
        "areas": [{"id": key, "name": name, "status": "partial", "implemented": implemented,
            "features": [{"name": label, "implemented": True, "adapter": tool,
                "adapter_available": catalog[tool]["workflow_execution_available"] if tool else None} for label, tool in FEATURES[key]],
            "adapters": [catalog[tool] for tool in tools], "missing": missing}
            for key, name, tools, implemented, missing in AREAS],
        "verification": "Implementation inventory, not a runtime scan or proof of effectiveness; run owned benchmarks and review their limits",
        "authorization": "Local operator attestations do not independently verify target-owner consent"}


def render_checklist():
    lines = ["# HunterQA feature readiness checklist", "",
        "Checked items are implemented bounded capabilities. Unchecked items remain unfinished.",
        "Every broad area is still partial. A source checkmark is not a live test, production approval or security certification.",
        "These are post-v1.3.0 development capabilities; the immutable release archive is unchanged.", ""]
    for index, (key, name, _, _, missing) in enumerate(AREAS, start=1):
        lines.extend([f"## {index}. {name} — partial", ""])
        lines.extend(f"- [x] {label}" for label, _ in FEATURES[key])
        lines.extend(f"- [ ] {label}" for label in missing)
        lines.append("")
    lines.extend(["## Additional Web Application review pack", "",
        "- [x] Ten narrow offline Python source cues with source hashes and remediation",
        "- [x] Six guided review contracts without automated detectors",
        "- [ ] Comprehensive active validation across all 16 skills",
        "", "See [the category guide](WEB_APPLICATION_REVIEW.md). Source cues remain unverified.", "",
        "## Additional Auth & Identity review pack", "",
        "- [x] Offline compact JWT sample comparisons against explicit review policy",
        "- [x] Offline declared OAuth/OIDC web-client configuration checks",
        "- [ ] Cryptographic JWT signature verification and server acceptance tests",
        "- [ ] End-to-end SSO, session and scope-enforcement validation",
        "", "See [the identity review guide](AUTH_IDENTITY_REVIEW.md). Declarations and decoded claims remain unverified.", "",
        "## Check your installation and owned lab", "",
        "Use `hunterqa assessment-readiness` for local installation/dependency checks.",
        "Run `assessment-benchmark --out-dir PRIVATE_PATH --authorized`, then",
        "`assessment-readiness --benchmark-dir PRIVATE_PATH --require-owned-lab` to recompute retained evidence.",
        "Real-world effectiveness remains unverified; AWS has synthetic API-contract tests only.",
        "See [the readiness guide](READINESS.md) and [adapter contracts](ASSESSMENT_ADAPTERS.md).", ""])
    return "\n".join(lines)
