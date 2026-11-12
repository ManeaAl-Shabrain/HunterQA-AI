"""Versioned synthetic inputs fed to the existing analysis implementations."""
import hashlib
import json
import os
from pathlib import Path

from . import assessment_modes
from .engagement import digest, utcnow

VERSION = "platform-demo-1"
LABELS = {
    "web": {"web-source.sqli"}, "business": {"business.role-boundary"},
    "network": {"network-review.network-attacks.vlan-segmentation-reviewed"}, "ad": {"ad-review.password-not-required"},
    "cloud": {"cloud-review." + provider + ".storage.public-access" for provider in ("aws", "azure", "gcp")},
    "iam": {"identity.oauth.pkce-policy"}, "vulnerability": {"hunterqa.docker.root-user", "hunterqa.docker.latest-tag"},
}


def business_fixture(unsafe=True):
    return {"schema_version": 1, "states": ["draft", "approved", "paid"],
        "transitions": [{"from": "draft", "to": "approved", "roles": ["approver"], "maximum_amount_cents": 10000, "same_tenant_required": True},
            {"from": "approved", "to": "paid", "roles": ["finance"], "maximum_amount_cents": 10000, "same_tenant_required": True}],
        "events": [{"id": "demo-event", "process_id": "demo-order", "from": "draft", "to": "approved",
            "role": "viewer" if unsafe else "approver", "amount_cents": 100, "same_tenant": True, "succeeded": True}]}


def fixtures(module, unsafe=True):
    if module == "business":
        return business_fixture(unsafe)
    if module == "network":
        from .network_review import PROFILES
        obs = {key: True for key in PROFILES["network-attacks"]}
        obs["vlan_segmentation_reviewed"] = not unsafe
        return {"schema_version": 1, "records": [{"id": "demo-network", "skill": "offensive-network-attacks", "observations": obs}]}
    if module == "ad":
        from .ad_review import SECTIONS
        data = {"schema_version": 1, "collected_at": utcnow().isoformat(), **{key: [] for key in SECTIONS}}
        data["accounts"] = [{"id": "demo-account", "enabled": True, "kind": "user", "tier0": False,
            "is_domain_controller": False, "user_account_control": 512 | (0x20 if unsafe else 0), "spn_count": 0}]
        return data
    if module == "cloud":
        return {"schema_version": 1, "records": [{"id": "demo-" + provider, "provider": provider, "area": "storage",
            "observations": {"public_access": unsafe, "encrypted_at_rest": True, "https_only": True, "access_logging": True}}
            for provider in ("aws", "azure", "gcp")]}
    if module == "iam":
        return {"schema_version": 1, "jwt_samples": [], "oauth_clients": [{"id": "demo-client", "client_type": "public", "oidc": True,
            "issuer": "https://identity.example.test", "authorization_endpoint": "https://identity.example.test/authorize",
            "token_endpoint": "https://identity.example.test/token", "redirect_uris": ["https://app.example.test/callback"],
            "response_types": ["code"], "grant_types": ["authorization_code"], "pkce_required": not unsafe,
            "pkce_methods": ["S256"], "state_required": True, "nonce_required": True, "redirect_matching": "exact"}]}
    raise ValueError("Unknown structured demonstration fixture")


def save(path, value):
    content = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)


def run(out_dir, *, module="all", authorized=False):
    if authorized is not True:
        raise PermissionError("Synthetic analysis requires --authorized")
    from .cli import _approved_root
    root = Path(out_dir).expanduser()
    if not root.is_absolute() or ".." in root.parts or root.exists():
        raise ValueError("Use a new absolute demo output directory")
    _approved_root(str(root.parent))
    if module != "all" and module not in assessment_modes.MODULES:
        raise ValueError("Unknown demonstration module")
    root.mkdir(mode=0o700)
    save(root / ".hunterqa-demo.json", {"execution_source": "DEMO", "dataset_version": VERSION})
    reports, controls, tp, fp, fn, tn = [], [], 0, 0, 0, 0
    for key in assessment_modes.MODULES if module == "all" else [module]:
        folder = root / key
        folder.mkdir(mode=0o700)
        results = []
        for unsafe in (False, True):
            case = folder / ("positive" if unsafe else "negative")
            case.mkdir(mode=0o700)
            if key in {"web", "vulnerability"}:
                if key == "web":
                    source = "def run(db,value):\n    db.execute(f'SELECT {value}')\n" if unsafe else "def run(db,value):\n    db.execute('SELECT ?', (value,))\n"
                    save(case / "app.py", source)
                else:
                    save(case / "Dockerfile", "FROM demo:latest\nUSER root\n" if unsafe else "FROM demo@sha256:" + "a" * 64 + "\nUSER 10001\n")
                from .web_review import review_project
                from .engines.config_audit import audit_project
                result = review_project(case) if key == "web" else {"findings": audit_project(case), "engine": "config-audit"}
                receipts = [{"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "relative_path_sha256": digest(p.name)} for p in case.iterdir()]
            elif key == "evidence":
                from .assessment_correlation import correlate
                body = digest("public-demo-witness")
                first = {"engine": "approved-scenario-suite", "schema_version": 1, "execution_source": "DEMO", "cases": [{"id": "demo-one", "kind": "workflow", "state": "matched", "receipts": [{"body_sha256": body}]}]}
                second = {"engine": "approved-scenario-suite", "schema_version": 1, "execution_source": "DEMO", "cases": [{"id": "demo-two", "kind": "workflow", "state": "matched", "receipts": [{"body_sha256": body if unsafe else digest("another-demo-witness")}]}]}
                paths = [case / "first.json", case / "second.json"]
                for path, value in zip(paths, (first, second)):
                    save(path, value)
                result = correlate(paths, authorized=True)
                receipts = [{"sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths]
            else:
                data = fixtures(key, unsafe)
                source = case / "fixture.json"
                save(source, data)
                from . import ad_review, cloud_review, identity_review, network_review, business_rules
                analyzer = {"ad": ad_review.review_evidence, "cloud": cloud_review.review_evidence,
                    "iam": identity_review.review_evidence, "network": network_review.review_evidence, "business": business_rules.review}[key]
                result = analyzer(data)
                receipts = [{"sha256": hashlib.sha256(source.read_bytes()).hexdigest()}]
            report = assessment_modes.envelope(key, "DEMO", result, receipts, origin="generated-synthetic")
            report["dataset_version"] = VERSION
            if key in LABELS:
                expected = LABELS[key] if unsafe else set()
                observed = {row["rule_id"] for row in report["findings"]}
                tp += len(expected & observed)
                fp += len(observed - expected)
                fn += len(expected - observed)
                tn += len(LABELS[key] - observed) if not unsafe else 0
                report["fixture_evaluation"] = {"expected_rules": sorted(expected), "observed_rules": sorted(observed), "matched": expected == observed}
            report_path = case / "report.json"
            save(report_path, report)
            results.append(len(result.get("links", [])) if key == "evidence" else len(report["findings"]))
            reports.append({"module": key, "case": "positive" if unsafe else "negative", "report_file": report_path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(), "execution_source": "DEMO"})
        controls.append({"module": key, "negative_count": results[0], "positive_count": results[1], "matched": results[0] == 0 and results[1] > 0})
    result = {"engine": "platform-demo-suite", "schema_version": 1, "execution_source": "DEMO", "synthetic": True,
        "dataset_version": VERSION, "reports": reports, "controls": controls, "network_requests": 0,
        "all_cases_matched": all(row["matched"] for row in controls) and not fp and not fn, "real_world_accuracy": "unverified",
        "fixture_metrics": {"true_positives": tp, "false_positives": fp, "false_negatives": fn, "true_negatives": tn,
            "precision": tp / (tp + fp) if tp + fp else None, "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "scope": "Ten selected rule labels in original synthetic positive/negative fixtures; evidence links excluded; not independent or representative field accuracy"}}
    save(root / "demo.json", result)
    return result
