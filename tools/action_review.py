"""GitHub Action helper: analyze an approved checkout as data; never build it."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath

import hunterqa
from hunterqa.orchestrator import scan_local_source
from hunterqa.research_workspace import _private_create
from hunterqa.sarif_export import export_sarif


def run_action(environment=None, *, scanner=scan_local_source):
    env = os.environ if environment is None else environment
    if env.get("HUNTERQA_ACTION_AUTHORIZED") != "true":
        raise PermissionError("Source action requires explicit authorized: true")
    requested = env.get("HUNTERQA_ACTION_PROJECT", ".")
    if (not isinstance(requested, str) or not requested or len(requested) > 1000
        or any(ord(c) < 32 for c in requested) or PureWindowsPath(requested).drive
        or PurePosixPath(requested).is_absolute() or ".." in PurePosixPath(requested.replace("\\", "/")).parts):
        raise ValueError("Choose a relative source directory within the checkout")
    fail_on = env.get("HUNTERQA_ACTION_FAIL_ON", "none")
    if fail_on not in ("none", "error"):
        raise ValueError("Action fail-on must be none or error (scanner labels, not verified impact)")
    checkout = Path(env["GITHUB_WORKSPACE"]).resolve(strict=True)
    source = (checkout / requested).resolve(strict=True)
    if not source.is_dir() or not source.is_relative_to(checkout):
        raise ValueError("Action source escaped the checkout")
    current = checkout
    for part in Path(requested).parts:
        current /= part
        if current.is_symlink():
            raise ValueError("Symlinked action project rejected")
    temporary = Path(env["RUNNER_TEMP"]).resolve(strict=True)
    if any(ord(c) < 32 for c in str(temporary)):
        raise ValueError("Invalid runner temporary directory")
    destination = Path(tempfile.mkdtemp(prefix="hunterqa-source-", dir=temporary))
    rules = Path(hunterqa.__file__).resolve().parent / "rules" / "semgrep.yml"
    result = scanner(source, rules)
    report, sarif = destination / "scan.json", destination / "results.sarif"
    _private_create(report, (json.dumps(result, indent=2) + "\n").encode())
    previous_roots = os.environ.get("HUNTERQA_APPROVED_ROOTS")
    os.environ["HUNTERQA_APPROVED_ROOTS"] = str(destination)
    try:
        _private_create(sarif, (json.dumps(export_sarif(report), indent=2) + "\n").encode())
    finally:
        if previous_roots is None:
            os.environ.pop("HUNTERQA_APPROVED_ROOTS", None)
        else:
            os.environ["HUNTERQA_APPROVED_ROOTS"] = previous_roots
    count = len(result["findings"])
    outputs = Path(env["GITHUB_OUTPUT"])
    if outputs.is_symlink() or not outputs.is_file():
        raise ValueError("Expected an existing runner output command file")
    with outputs.open("a", encoding="utf-8") as stream:
        stream.write(f"sarif_path={sarif}\ncandidate_count={count}\n")
    return 3 if fail_on == "error" and any(row.get("severity") == "ERROR" for row in result["findings"]) else 0


if __name__ == "__main__":
    raise SystemExit(run_action())
