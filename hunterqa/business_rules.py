"""Review explicit owner-provided process definitions and observed audit events.

No target requests, inferred business rules or expression evaluation.
"""
import re

ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")


def review(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "states", "transitions", "events"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Invalid business process evidence")
    states = data["states"]
    if not isinstance(states, list) or not 1 <= len(states) <= 30 or any(not isinstance(v, str) or not ID.fullmatch(v) for v in states) or len(set(states)) != len(states):
        raise ValueError("Define unique bounded business states")
    if not isinstance(data["transitions"], list) or not 1 <= len(data["transitions"]) <= 100 or not isinstance(data["events"], list) or len(data["events"]) > 500:
        raise ValueError("Bound process rules and events")
    rules = {}
    for rule in data["transitions"]:
        if not isinstance(rule, dict) or set(rule) != {"from", "to", "roles", "maximum_amount_cents", "same_tenant_required"}:
            raise ValueError("Invalid transition rule")
        if rule["from"] not in states or rule["to"] not in states or (rule["from"], rule["to"]) in rules:
            raise ValueError("Unknown or duplicate transition")
        if not isinstance(rule["roles"], list) or not 1 <= len(rule["roles"]) <= 10 or any(not isinstance(v, str) or not ID.fullmatch(v) for v in rule["roles"]):
            raise ValueError("Use bounded explicit roles")
        if type(rule["maximum_amount_cents"]) is not int or not 0 <= rule["maximum_amount_cents"] <= 10**12 or type(rule["same_tenant_required"]) is not bool:
            raise ValueError("Use explicit amount and tenant constraints")
        rules[rule["from"], rule["to"]] = rule
    findings, seen, last = [], set(), {}
    for event in data["events"]:
        keys = {"id", "process_id", "from", "to", "role", "amount_cents", "same_tenant", "succeeded"}
        if not isinstance(event, dict) or set(event) != keys:
            raise ValueError("Invalid process event")
        if any(not isinstance(event[k], str) or not ID.fullmatch(event[k]) for k in ("id", "process_id", "role")) or event["id"] in seen:
            raise ValueError("Unique neutral event identifiers required")
        if event["from"] not in states or event["to"] not in states or type(event["amount_cents"]) is not int or abs(event["amount_cents"]) > 10**12 or any(type(event[k]) is not bool for k in ("same_tenant", "succeeded")):
            raise ValueError("Invalid observed transition values")
        seen.add(event["id"])
        if not event["succeeded"]:
            continue
        rule = rules.get((event["from"], event["to"]))
        problems = []
        if last.get(event["process_id"], event["from"]) != event["from"]:
            problems.append(("state-continuity", "Observed successful process states are discontinuous"))
        if rule is None:
            problems.append(("unapproved-transition", "Observed successful transition is outside the declared process"))
        else:
            if event["role"] not in rule["roles"]:
                problems.append(("role-boundary", "Observed successful transition violates the declared role restriction"))
            if not 0 <= event["amount_cents"] <= rule["maximum_amount_cents"]:
                problems.append(("transaction-limit", "Observed successful transaction violates the declared amount limit"))
            if rule["same_tenant_required"] and not event["same_tenant"]:
                problems.append(("tenant-boundary", "Observed successful transition violates the declared tenant boundary"))
        last[event["process_id"]] = event["to"]
        for key, title in problems:
            findings.append({"rule_id": "business." + key, "test_case": event["id"], "title": title,
                "severity": "WARNING", "cwe": "CWE-840", "file_path": "external-evidence", "line_start": 1,
                "message": title, "remediation": "Verify the original event and intended business rule; enforce the transition, role, tenant and transaction constraint server-side.",
                "verification_status": "unverified", "engine": "business-process-review"})
    return {"engine": "business-process-review", "schema_version": 1, "findings": findings,
        "events_reviewed": len(seen), "network_requests": 0,
        "limitations": ["Supplied process rules and event declarations; no automatic process discovery or proof of target behavior",
            "Missing events, concurrency, external side effects and complete transaction semantics remain unassessed"]}
