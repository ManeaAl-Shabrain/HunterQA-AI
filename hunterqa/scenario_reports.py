"""Allowlisted saved summaries. Loading a file never executes a scenario."""
import re

from .bounty import _approved_file
from .cloud_inventory_common import bounded_json
from .source_files import read_bounded


def summary(path):
    result = {"status": "not_configured", "rows": [], "engine": None}
    if not path:
        return result
    try:
        report = bounded_json(read_bounded(_approved_file(path), 1048576))
        if type(report.get("schema_version")) is not int or report["schema_version"] != 1:
            raise ValueError
        engine = report.get("engine")
        rows = []
        if engine == "unified-assessment-review":
            from .assessment_modes import load_report
            checked = load_report(path)
            return {"status": "ready", "engine": engine, "rows": [], "assessment": checked}
        elif engine == "approved-scenario-suite":
            if not isinstance(report.get("cases"), list) or len(report["cases"]) > 10:
                raise ValueError
            for row in report["cases"]:
                if (not isinstance(row, dict) or not isinstance(row.get("id"), str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", row["id"])
                        or row.get("kind") not in {"workflow", "browser-journey", "xss-context", "sqli-boolean", "sqli-timing", "ssrf-callback", "upload-canary"}
                        or row.get("state") not in {"matched", "different", "not_observed", "inconclusive", "timing_signal"}):
                    raise ValueError
                rows.append({"id": row["id"], "kind": row["kind"], "state": row["state"]})
        elif engine == "normalized-access-graph":
            if report.get("domain") not in {"active-directory", "aws", "azure", "gcp"} or not isinstance(report.get("queries"), list) or len(report["queries"]) > 200:
                raise ValueError
            for index, row in enumerate(report["queries"]):
                if not isinstance(row, dict) or row.get("model_result") not in {"allow", "deny", "unknown", "not-granted-in-snapshot"}:
                    raise ValueError
                rows.append({"id": str(index + 1), "kind": report["domain"] + "-model", "state": row["model_result"]})
        elif engine == "scoped-service-fingerprint":
            if report.get("protocol") not in {"ssh", "smtp", "ftp", "redis", "http"} or report.get("outcome") not in {"observed", "unrecognized-response", "inconclusive"}:
                raise ValueError
            rows.append({"id": "endpoint", "kind": report["protocol"], "state": report["outcome"]})
        elif engine == "assessment-evidence-index":
            if not isinstance(report.get("links"), list) or len(report["links"]) > 200:
                raise ValueError
            for index, row in enumerate(report["links"]):
                if not isinstance(row, dict) or row.get("meaning") != "matching-digest-only":
                    raise ValueError
                rows.append({"id": str(index + 1), "kind": "evidence-link", "state": "matching-digest-only"})
        else:
            raise ValueError
        return {"status": "ready", "engine": engine, "rows": rows}
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, RecursionError):
        return {"status": "unavailable", "rows": [], "engine": None}
