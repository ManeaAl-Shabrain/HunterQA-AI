"""Explicit local laboratory operations only. Not a security boundary/sandbox.

Never execute untrusted code outside a separately isolated VM/container.
No browser endpoint launches these commands and no network target is accepted.
"""
from __future__ import annotations
import hashlib
import json
import os
import signal
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from .sanitizers import parse_sanitizer_log

MAX_CRASH_INPUT = 1024 * 1024


def _within(path: Path, root: Path) -> Path:
    root = root.expanduser().resolve(strict=True)
    path = path.expanduser().resolve(strict=True)
    if not path.is_relative_to(root):
        raise ValueError("Path outside the explicitly approved local lab")
    return path


def _limits():
    import resource  # POSIX-only; importing offline research modules remains portable.
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    # ASan reserves enormous virtual address space: RLIMIT_AS would break ASan.
    # Run only in an isolated VM with host-level memory limits.
    resource.setrlimit(resource.RLIMIT_FSIZE, (20 * 1024**2, 20 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))


def _replay(binary: Path, data: bytes, timeout: float = 5) -> dict:
    # Use a temporary file so verbose/untrusted stderr cannot exhaust Python RAM.
    with tempfile.TemporaryFile() as stderr_file:
        proc = subprocess.Popen([str(binary)], stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL, stderr=stderr_file,
                                cwd=str(binary.parent), env={
                                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                    "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1",
                                    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
                                }, start_new_session=True, preexec_fn=_limits)
        try:
            proc.communicate(input=data, timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            timed_out = True
        stderr_file.seek(0)
        err = stderr_file.read(16_000)
    diag = err[:16_000].decode("utf-8", errors="replace")
    return {"return_code": proc.returncode, "signal": -proc.returncode if proc.returncode < 0 else None,
            "timed_out": timed_out, "diagnostic": diag,
            "classification": parse_sanitizer_log(diag)}


def verify_crashes(*, approved_lab: Path, binary_path: Path, crash_dir: Path,
                   output: Path, authorized: bool, max_crashes: int = 30) -> dict:
    if not authorized:
        raise PermissionError("Use explicit --authorized for this local lab")
    if os.name != "posix":
        raise RuntimeError("Executable crash replay requires a separately isolated POSIX lab")
    if type(max_crashes) is not int or not 1 <= max_crashes <= 100:
        raise ValueError("Crash replay budget must be 1..100")
    root = approved_lab.expanduser().resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Invalid approved laboratory")
    binary = _within(binary_path, root)
    inputs_dir = _within(crash_dir, root)
    if not binary.is_file() or not os.access(binary, os.X_OK) or not inputs_dir.is_dir():
        raise ValueError("Binary must be executable and crash path must be a directory")
    if binary_path.is_symlink() or crash_dir.is_symlink():
        raise ValueError("Symlink inputs are forbidden")
    if output.expanduser().resolve().is_relative_to(root) is False:
        raise ValueError("Output must stay inside approved laboratory")
    if output.exists() or output.is_symlink():
        raise ValueError("Use a new crash replay output file")
    if binary.stat().st_size > 100 * 1024 * 1024:
        raise ValueError("Approved binary exceeds 100 MB")
    hash_state = hashlib.sha256()
    with binary.open("rb") as stream:
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            hash_state.update(chunk)
    binary_digest = hash_state.hexdigest()
    rows = []
    diagnostics = []
    for crash in sorted(inputs_dir.iterdir()):
        if len(rows) >= min(max_crashes, 100):
            break
        if crash.is_symlink() or not crash.is_file() or not crash.name.startswith("id:") or crash.stat().st_size > MAX_CRASH_INPUT:
            continue
        with crash.open("rb") as stream:
            data = stream.read(MAX_CRASH_INPUT + 1)
        if len(data) > MAX_CRASH_INPUT:
            continue
        digest = hashlib.sha256(data).hexdigest()
        attempts = [_replay(binary, data) for _ in range(3)]
        outcomes = [(a["return_code"], a["classification"]["category"], a["timed_out"]) for a in attempts]
        reproducible = len(set(outcomes)) == 1 and not attempts[0]["timed_out"] and attempts[0]["return_code"] != 0
        row = {"filename": crash.name, "sha256": digest, "binary_sha256": binary_digest,
               "input_size": len(data), "attempts": attempts,
               "reproducible": reproducible, "sanitizer_confirmed": reproducible and all(a["classification"]["evidence_confirmed"] for a in attempts),
               "category": attempts[0]["classification"]["category"] or "unclassified",
               "cwe_candidate": attempts[0]["classification"]["cwe_candidate"] if reproducible and all(a["classification"]["evidence_confirmed"] for a in attempts) else None,
               "verification_status": "sanitizer_evidence_requires_review" if reproducible and all(a["classification"]["evidence_confirmed"] for a in attempts) else "requires_source_review",
               "zero_day_confirmed": False}
        rows.append(row)
        if row["sanitizer_confirmed"]:
            diag = dict(attempts[0]["classification"])
            diag.update({"input_sha256": digest, "binary_sha256": binary_digest})
            diagnostics.append(diag)
    result = {"project": "HunterQA AI", "engine": "AFL++ crash replay + ASan/UBSan", "generated_at": datetime.now(timezone.utc).isoformat(),
              "total_crashes": len(rows), "findings": rows, "sanitizer_evidence": diagnostics,
              "summary": {"total_crashes": len(rows), "sanitizer_diagnostics": len(diagnostics),
                          "zero_days_confirmed": 0, "review_required": True}, "integration_version": "unified"}
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    return result
