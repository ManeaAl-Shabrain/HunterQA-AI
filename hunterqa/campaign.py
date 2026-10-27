"""One authorized, bounded LOCAL research campaign.

Sequential stages reuse existing engines. Evidence is never silently merged
across unrelated programs, and no model output is executed or applied.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .orchestrator import scan_local_source
from .engines.trust_graph import build_trust_graph
from .engines.ai_research import analyze_local
from .engines.sanitizers import parse_sanitizer_log
from .engines.fuzzing import verify_crashes
from .engines.triage import triage_reports

MAX_REPORT_BYTES = 2_000_000
MAX_SANITIZER_LOG = 500_000
KINDS = ("scan", "graph", "ai", "replay", "sanitizer", "triage")


def _approved_roots() -> list[Path]:
    raw = os.environ.get("HUNTERQA_APPROVED_ROOTS", "")
    roots = []
    for entry in raw.split(os.pathsep):
        if entry:
            root = Path(entry).expanduser().resolve(strict=True)
            if not root.is_dir():
                raise ValueError("Approved root must be a directory")
            roots.append(root)
    if not roots:
        raise ValueError("Set HUNTERQA_APPROVED_ROOTS to explicit local directories")
    return roots


def _approved_existing(path: str | Path, roots: list[Path], *, directory: bool):
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise ValueError("Symlinked campaign inputs are not permitted")
    resolved = candidate.resolve(strict=True)
    if not any(resolved.is_relative_to(root) for root in roots):
        raise ValueError("Campaign input is outside approved roots")
    if (not resolved.is_dir() if directory else not resolved.is_file()):
        raise ValueError("Wrong campaign input file type")
    # Reject symlink traversal BELOW the approved root, not just at the leaf.
    for root in roots:
        if resolved.is_relative_to(root):
            current = root
            for part in resolved.relative_to(root).parts:
                current /= part
                if current.is_symlink():
                    raise ValueError("Symlinked campaign path component")
            break
    return resolved


def _new_output_dir(path: str | Path, roots: list[Path], project: Path):
    candidate = Path(path).expanduser().absolute()
    if candidate.name in ("", ".", "..") or candidate.exists() or candidate.is_symlink():
        raise ValueError("Use a new, unused campaign output directory")
    parent = _approved_existing(candidate.parent, roots, directory=True)
    output = parent / candidate.name
    if output.is_relative_to(project) or project.is_relative_to(output):
        raise ValueError("Keep research output separate from the scanned source")
    output.mkdir(mode=0o700, exist_ok=False)
    return output


def _write_json(path: Path, value: dict) -> str:
    data = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Engine artifact exceeds 2 MB")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return hashlib.sha256(data).hexdigest()


def run_campaign(
    project: str | Path,
    out_dir: str | Path,
    *,
    authorized: bool,
    include_graph: bool = True,
    include_ai: bool = False,
    ai_max_chunks: int = 4,
    ai_model: str = "qwen2.5-coder:3b",
    sanitizer_log: str | Path | None = None,
    replay_lab: str | Path | None = None,
    replay_binary: str | Path | None = None,
    replay_crashes: str | Path | None = None,
    replay_max_crashes: int = 3,
    scan_timeout: int = 900,
) -> dict:
    """Run selected local engines once, writing an immutable artifact set.

    Returns a manifest with skipped/failed stages. This is not a sandbox.
    Replay is only appropriate in an already isolated, authorized VM.
    """
    if not authorized:
        raise PermissionError("A campaign requires explicit --authorized")
    if not 1 <= ai_max_chunks <= 16:
        raise ValueError("AI chunk budget must be 1..16")
    if not 1 <= replay_max_crashes <= 10:
        raise ValueError("Replay limit must be 1..10")
    replay_inputs = (replay_lab, replay_binary, replay_crashes)
    if any(x is not None for x in replay_inputs) and not all(
        x is not None for x in replay_inputs
    ):
        raise ValueError("Replay requires --lab, --binary and --crashes together")

    roots = _approved_roots()
    source = _approved_existing(project, roots, directory=True)
    log = (_approved_existing(sanitizer_log, roots, directory=False)
           if sanitizer_log is not None else None)
    if log is not None and log.stat().st_size > MAX_SANITIZER_LOG:
        raise ValueError("Sanitizer log exceeds 500 KB")
    lab = binary = crashes = None
    if all(x is not None for x in replay_inputs):
        lab = _approved_existing(replay_lab, roots, directory=True)
        binary = _approved_existing(replay_binary, roots, directory=False)
        crashes = _approved_existing(replay_crashes, roots, directory=True)
        if not binary.is_relative_to(lab) or not crashes.is_relative_to(lab):
            raise ValueError("Replay files must be inside the approved lab")

    # Do not make a directory (or execute a stage) until the scope is checked.
    output = _new_output_dir(out_dir, roots, source)
    if lab is not None and not output.is_relative_to(lab):
        raise ValueError("For replay, output folder must be inside --lab")

    now = lambda: datetime.now(timezone.utc).isoformat()
    manifest = {
        "schema_version": 1,
        "engine": "hunterqa_authorized_local_campaign",
        "project": str(source),
        "output_directory": str(output),
        "started_at": now(),
        "finished_at": None,
        "stages": {key: {"status": "skipped"} for key in KINDS},
        "artifacts": {},
        "summary": {"research_records": 0, "zero_days_confirmed": 0},
        "human_review_required": True,
        "source_modified": False,
        "limitations": (
            "Offline static analysis and optional bounded Ollama research; "
            "optional crash replay executes a local test binary ONLY on explicit "
            "request inside a separately isolated VM. Findings are not confirmed "
            "vulnerabilities, exploitability proofs or zero-days."
        ),
    }
    sources: dict[str, Path] = {}

    def stage(name: str, action):
        try:
            result = action()
            dest = output / f"{name}.json"
            # verify_crashes writes its own replay.json inside the lab.
            if name == "replay":
                if not dest.is_file():
                    raise ValueError("Replay did not write its artifact")
                raw = dest.read_bytes()
                if len(raw) > MAX_REPORT_BYTES:
                    raise ValueError("Replay artifact too large")
                digest = hashlib.sha256(raw).hexdigest()
            else:
                digest = _write_json(dest, result)
            state = ("partial" if result.get("analysis_status") == "partial"
                     else "completed")
            manifest["stages"][name] = {"status": state, "sha256": digest}
            manifest["artifacts"][name] = {"file": dest.name, "sha256": digest}
            sources[name] = dest
        except Exception as exc:
            # No stacktrace, source contents or unexpected model data in metadata.
            manifest["stages"][name] = {
                "status": "failed", "error_type": type(exc).__name__,
            }

    rules = Path(__file__).resolve().parent / "rules" / "semgrep.yml"
    stage("scan", lambda: scan_local_source(source, rules, timeout=scan_timeout))

    if include_graph:
        stage("graph", lambda: build_trust_graph(source))
    if include_ai:
        stage("ai", lambda: analyze_local(
            source, model=ai_model, max_files=40,
            max_chunks=ai_max_chunks, batch_size=2,
        ))
    if lab is not None:
        stage("replay", lambda: verify_crashes(
            approved_lab=lab, binary_path=binary, crash_dir=crashes,
            output=output / "replay.json", authorized=True,
            max_crashes=replay_max_crashes,
        ))
    if log is not None:
        stage("sanitizer", lambda: parse_sanitizer_log(
            log.read_text(encoding="utf-8", errors="replace")
        ))

    if sources:
        stage("triage", lambda: triage_reports(sources))
        if "triage" in sources:
            manifest["summary"]["research_records"] = len(
                json.loads(sources["triage"].read_text(encoding="utf-8"))
                .get("findings", [])
            )
    manifest["finished_at"] = now()
    manifest["summary"]["completed_stages"] = sum(
        v["status"] == "completed" for v in manifest["stages"].values()
    )
    manifest["summary"]["failed_stages"] = sum(
        v["status"] == "failed" for v in manifest["stages"].values()
    )
    manifest["summary"]["zero_days_confirmed"] = 0
    _write_json(output / "manifest.json", manifest)
    return manifest
