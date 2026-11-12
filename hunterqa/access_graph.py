"""Bounded exact-action entitlement model for AD and cloud evidence snapshots.

This evaluates supplied normalized evidence, not Windows DACL or provider IAM
semantics. A graph path is not an executed privilege escalation.
"""
from collections import deque
import hashlib
import re

from .bounty import _approved_file, _decode_json
from .engagement import _expiry, utcnow
from .source_files import read_bounded

DOMAINS = {"active-directory", "aws", "azure", "gcp"}
CONTROL = {"GenericAll", "WriteDacl", "WriteOwner", "AddMember", "assume-role", "act-as", "administer"}


def fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("Unknown or missing access graph fields")


def identifier(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or not all(33 <= ord(c) < 127 for c in value):
        raise ValueError("Expected a bounded non-secret identifier")
    return value


def rows(data, name, maximum):
    value = data[name]
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError("Access graph collection exceeds its bound")
    return value


def validate(data):
    fields(data, {"schema_version", "domain", "collected_at", "principals", "resources", "memberships", "grants", "queries", "paths"})
    if type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["domain"] not in DOMAINS:
        raise ValueError("Unsupported authorization model")
    age = (utcnow() - _expiry(data["collected_at"])).total_seconds()
    if not -60 <= age <= 86400:
        raise ValueError("Use a snapshot collected within the last day")
    principals, resources = {}, {}
    for name, target, maximum in (("principals", principals, 200), ("resources", resources, 500)):
        for row in rows(data, name, maximum):
            fields(row, {"id", "tenant", "enabled", "kind"} if name == "principals" else {"id", "tenant"})
            key = identifier(row["id"])
            identifier(row["tenant"])
            if key in target:
                raise ValueError("Duplicate graph identifier")
            if name == "principals" and (type(row["enabled"]) is not bool or row["kind"] not in {"user", "group", "role", "service"}):
                raise ValueError("Invalid principal")
            target[key] = row
    if not principals or not resources:
        raise ValueError("Supply principals and resources")
    for row in rows(data, "memberships", 1000):
        fields(row, {"member", "group", "source_sha256"})
        if (row["member"] not in principals or row["group"] not in principals
                or principals[row["group"]]["kind"] not in {"group", "role"}):
            raise ValueError("Membership references an unavailable group")
        if not isinstance(row["source_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", row["source_sha256"]):
            raise ValueError("Membership needs an evidence digest")
    for row in rows(data, "grants", 1000):
        fields(row, {"principal", "resource", "actions", "effect", "condition", "source_sha256"})
        if row["principal"] not in principals or row["resource"] not in resources:
            raise ValueError("Grant references an unavailable object")
        if (not isinstance(row["actions"], list) or not 1 <= len(row["actions"]) <= 50
                or any(not isinstance(action, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:/-]{0,127}", action) for action in row["actions"])
                or len(set(row["actions"])) != len(row["actions"])
                or row["effect"] not in {"allow", "deny"} or row["condition"] not in {"satisfied", "unsatisfied", "unknown"}
                or not isinstance(row["source_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", row["source_sha256"])):
            raise ValueError("Use exact actions and explicit condition/evidence states")
    for row in rows(data, "queries", 200):
        fields(row, {"principal", "resource", "action", "expected"})
        if (row["principal"] not in principals or row["resource"] not in resources
                or not isinstance(row["action"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:/-]{0,127}", row["action"])
                or row["expected"] not in {"allow", "deny"}):
            raise ValueError("Invalid exact-action query")
    for row in rows(data, "paths", 5):
        fields(row, {"start", "target"})
        if row["start"] not in principals or row["target"] not in resources:
            raise ValueError("Invalid path endpoints")
    return principals, resources


def evaluate(data):
    principals, resources = validate(data)
    closures, membership_evidence, indexed, membership_index = {}, {}, {}, {}
    for edge in data["memberships"]:
        membership_index.setdefault(edge["member"], []).append(edge)
    for grant in data["grants"]:
        for action in grant["actions"]:
            indexed.setdefault((grant["resource"], action), []).append(grant)
    for principal in principals:
        reached, queue = {principal}, deque([principal])
        evidence = set()
        while queue:
            member = queue.popleft()
            for edge in membership_index.get(member, []):
                if edge["member"] == member and edge["group"] not in reached and principals[edge["group"]]["enabled"]:
                    reached.add(edge["group"])
                    queue.append(edge["group"])
                    evidence.add(edge["source_sha256"])
        closures[principal] = reached
        membership_evidence[principal] = evidence

    def decision(principal, resource, action):
        if not principals[principal]["enabled"]:
            return "deny", []
        applicable = [row for row in indexed.get((resource, action), []) if row["principal"] in closures[principal]
            and row["condition"] != "unsatisfied"]
        if any(row["effect"] == "deny" and row["condition"] == "satisfied" for row in applicable):
            result = "deny"
        elif any(row["effect"] == "deny" and row["condition"] == "unknown" for row in applicable):
            result = "unknown"
        elif any(row["effect"] == "allow" and row["condition"] == "satisfied" for row in applicable):
            result = "allow"
        elif applicable:
            result = "unknown"
        else:
            result = "not-granted-in-snapshot"
        return result, sorted({row["source_sha256"] for row in applicable} | (membership_evidence[principal] if applicable else set()))[:20]

    queries = []
    for row in data["queries"]:
        result, evidence = decision(row["principal"], row["resource"], row["action"])
        queries.append({"principal_sha256": fingerprint(row["principal"]), "resource_sha256": fingerprint(row["resource"]),
            "action": row["action"], "expected": row["expected"], "model_result": result,
            "contract_state": "matched" if result == row["expected"] else "inconclusive" if result in {"unknown", "not-granted-in-snapshot"} else "different",
            "cross_tenant": principals[row["principal"]]["tenant"] != resources[row["resource"]]["tenant"], "evidence_sha256": evidence,
            "evidence_may_be_truncated": len(evidence) >= 20})
    paths = []
    for contract in data["paths"]:
        queue, found, expanded = deque([(contract["start"], [contract["start"]], [])]), [], 0
        clipped = False
        while queue and len(found) < 10 and expanded < 2000:
            node, trail, proofs = queue.popleft()
            expanded += 1
            if node == contract["target"]:
                found.append({"nodes_sha256": [fingerprint(value) for value in trail], "evidence_sha256": sorted(set(proofs))[:20],
                    "evidence_may_be_truncated": len(proofs) >= 20})
                continue
            if len(trail) >= 6 or node not in principals or not principals[node]["enabled"]:
                continue
            neighbours = set()
            for resource, action in indexed:
                if resource in trail or resource in neighbours or action not in CONTROL:
                    continue
                result, evidence = decision(node, resource, action)
                if result == "allow":
                    if len(queue) < 2000:
                        neighbours.add(resource)
                        queue.append((resource, trail + [resource], sorted(set(proofs + evidence))[:40]))
                    else:
                        clipped = True
        paths.append({"start_sha256": fingerprint(contract["start"]), "target_sha256": fingerprint(contract["target"]),
            "candidate_paths": found, "truncated": bool(queue) or clipped, "execution_verified": False})
    return {"engine": "normalized-access-graph", "schema_version": 1, "domain": data["domain"],
        "queries": queries, "paths": paths, "principals": len(principals), "resources": len(resources),
        "network_requests": 0, "effective_live_access_verified": False, "review_required": True,
        "limitations": ["Exact-action supplied-evidence model; no wildcard, Windows ACE ordering, IAM condition language, SCP, resource-policy or live directory evaluation",
            "Unknown conditions and missing grants remain inconclusive; snapshot paths are candidates, not executed attack paths"]}


def review(input_file, *, authorized=False):
    if authorized is not True:
        raise PermissionError("Access graph review requires --authorized")
    raw = read_bounded(_approved_file(input_file), 1048576)
    result = evaluate(_decode_json(raw))
    result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    return result
