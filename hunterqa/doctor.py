"""HunterQA AI release doctor: local, read-only configuration checks.

No source scans, subprocess execution, model inference, or writes.
The optional Ollama check connects ONLY to fixed loopback 127.0.0.1,
rejects redirects and bypasses network proxies.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping


OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"
MAX_OLLAMA_RESPONSE = 65536
STATUS_VALUES = {"ok", "warning", "fail", "skipped"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def probe_local_ollama() -> set[str]:
    """Read a bounded list of installed models. No remote host or redirect."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(),
    )
    request = urllib.request.Request(
        OLLAMA_TAGS_URL,
        headers={"Accept": "application/json"},
        method="GET",
    )
    with opener.open(request, timeout=2) as response:
        if response.geturl() != OLLAMA_TAGS_URL:
            raise ValueError("Unexpected Ollama destination")
        body = response.read(MAX_OLLAMA_RESPONSE + 1)
    if len(body) > MAX_OLLAMA_RESPONSE:
        raise ValueError("Ollama returned oversized metadata")
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("models"), list):
        raise ValueError("Unexpected Ollama response")
    models = set()
    for item in data["models"][:200]:
        if isinstance(item, dict):
            name = item.get("name") or item.get("model")
            if isinstance(name, str):
                models.add(name[:120])
    return models


def _root_is_safe(directory: Path) -> bool:
    """Reject symlinked path components and nonexistent roots."""
    if not directory.is_absolute():
        return False
    current = Path(directory.anchor)
    try:
        for piece in directory.parts[1:]:
            current /= piece
            if current.is_symlink():
                return False
        return directory.is_dir()
    except OSError:
        return False


def run_diagnostics(
    *,
    project: str | None = None,
    check_ollama: bool = False,
    environment: Mapping[str, str] | None = None,
    rules: Path | None = None,
) -> dict:
    """Collect non-destructive readiness information without sensitive values.

    'fail' means an essential check did not pass. 'warning' is a limitation,
    not proof of compromise. 'ok' is not a security certification.
    """
    env = environment if environment is not None else os.environ
    checks = []

    def add(name: str, status: str, detail: str) -> None:
        assert status in STATUS_VALUES
        checks.append({"name": name, "status": status, "detail": detail})

    add(
        "python",
        "ok" if sys.version_info >= (3, 11) else "fail",
        "Python 3.11 or newer required",
    )
    add(
        "flask",
        "ok" if importlib.util.find_spec("flask") is not None else "fail",
        "Dashboard Python package availability",
    )
    add(
        "semgrep",
        "ok" if shutil.which("semgrep") is not None else "fail",
        "Offline static analysis executable availability",
    )

    rules_file = Path(rules) if rules is not None else (
        Path(__file__).resolve().parent / "rules" / "semgrep.yml"
    )
    try:
        rules_ok = rules_file.is_file() and 0 < rules_file.stat().st_size <= 2_000_000
    except OSError:
        rules_ok = False
    add("local_rules", "ok" if rules_ok else "fail", "Bundled local Semgrep rules")

    raw_roots = env.get("HUNTERQA_APPROVED_ROOTS") or env.get("ZEROSCOPE_APPROVED_ROOTS", "")
    entries = [value for value in raw_roots.split(os.pathsep) if value.strip()]
    roots = [Path(value).expanduser().absolute() for value in entries]
    valid_roots = [r for r in roots if _root_is_safe(r)]
    roots_status = "ok" if roots and len(valid_roots) == len(roots) else "fail"
    add("approved_roots", roots_status,
        f"{len(valid_roots)} valid local roots out of {len(roots)} configured; no root paths exposed")

    if project is None:
        add("project_scope", "skipped", "No project was supplied")
    else:
        try:
            target = Path(project).expanduser().absolute()
            resolved_target = target.resolve(strict=True)
            in_scope = (
                target.is_dir()
                and _root_is_safe(target)
                and any(resolved_target.is_relative_to(r.resolve(strict=True)) for r in valid_roots)
            )
        except (OSError, ValueError, RuntimeError):
            in_scope = False
        add("project_scope", "ok" if in_scope else "fail",
            "Project is within an approved local root" if in_scope
            else "Project is missing, symlinked, or outside approved local roots")

    key = env.get("HUNTERQA_SECRET_KEY") or env.get("ZEROSCOPE_SECRET_KEY")
    add(
        "session_key",
        "ok" if key and len(key) >= 32 else "warning",
        "Persistent high-entropy session secret configured" if key and len(key) >= 32
        else "No persistent 32+ character session secret; sessions may reset after restart",
    )

    add(
        "loopback_server",
        "ok",
        "Bundled run.py is designed for 127.0.0.1; check process binding separately",
    )

    if check_ollama:
        try:
            models = probe_local_ollama()
            desired = env.get("HUNTERQA_OLLAMA_MODEL") or "qwen2.5-coder:3b"
            found = desired in models
            add(
                "ollama_model",
                "ok" if found else "warning",
                "Local Ollama reachable and requested model installed" if found
                else "Local Ollama reachable, but requested model is not listed",
            )
        except (OSError, ValueError, TimeoutError, urllib.error.URLError,
                json.JSONDecodeError, UnicodeError):
            add(
                "ollama_model", "warning",
                "Optional local Ollama model list unavailable; no remote fallback",
            )
    else:
        add("ollama_model", "skipped", "Opt in with --check-ollama for a loopback-only metadata check")

    counts = {status: sum(c["status"] == status for c in checks)
              for status in ("ok", "warning", "fail", "skipped")}
    return {
        "schema_version": 1,
        "engine": "hunterqa_local_release_doctor",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": counts,
        "overall": "not_ready" if counts["fail"] else
                   ("ready_with_warnings" if counts["warning"] else "ready"),
        "source_code_executed": False,
        "remote_network_access": False,
        "changes_made": False,
        "security_certification": False,
    }
