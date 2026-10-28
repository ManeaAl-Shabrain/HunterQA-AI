"""Original review playbooks and a private, non-executing research journal.

Hash links detect inconsistency, not forgery by someone who controls the folder.
Resuming a journal returns context only; it never resumes network operations.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path

from .bounty import _approved_file, _read_json
from .engagement import _policy_snapshot, digest, utcnow
from .source_files import read_bounded

PLAYBOOKS = (
    {"id": "source-boundaries", "title": "Source trust boundaries", "questions": [
        "Which untrusted inputs reach sensitive operations?", "Where are validation and least privilege enforced?",
        "What benign control case distinguishes a risky pattern from intended behavior?"]},
    {"id": "api-authorization", "title": "API authorization review", "questions": [
        "Which operations declare anonymous, optional, or required authentication?",
        "What owner/tenant rules should hold for designated test identities?",
        "Which expected denial and permitted access examples document that rule?"]},
    {"id": "session-controls", "title": "Session and account controls", "questions": [
        "Which dedicated disposable account and login endpoint are approved?",
        "What observable signal would establish a session beyond an HTTP status?",
        "Which cookie, expiry, logout, and CSRF expectations require manual review?"]},
    {"id": "dependency-review", "title": "Dependency evidence", "questions": [
        "Is the version resolved, declared exactly, or only a constraint?",
        "Is the advisory current, non-withdrawn, and applicable to the ecosystem?",
        "What installed-version and reachability evidence is still missing?"]},
    {"id": "container-config", "title": "Container configuration", "questions": [
        "Are identities, capabilities, mounts, and privileges necessary?",
        "Which network and secret boundaries are declared locally?",
        "Which configuration evidence needs deployment confirmation?"]},
    {"id": "pipeline-review", "title": "CI and supply-chain review", "questions": [
        "Where can untrusted contribution data reach privileged jobs?",
        "Are credentials and artifact upload permissions narrowly scoped?",
        "Which pinned inputs and reproducible checks support the conclusion?"]},
    {"id": "response-controls", "title": "Response and browser controls", "questions": [
        "What application context makes a header or cookie observation relevant?",
        "Does an expected-status match have an independent behavioral control?",
        "Are redirects, rate limits, and incomplete observations recorded explicitly?"]},
    {"id": "ai-output-review", "title": "AI evidence grounding", "questions": [
        "Does each suggestion cite an actual approved source location or artifact?",
        "What contradicting evidence or negative result has been recorded?",
        "Can a human separate an observation, a hypothesis, and a validated impact?"]},
    {"id": "business-workflows", "title": "Business workflow review", "questions": [
        "Which business invariants and test records are approved for review?",
        "What expected versus observed state would demonstrate a discrepancy?",
        "Which cleanup and non-sensitive evidence requirements apply?"]},
    {"id": "data-handling", "title": "Data handling and disclosure", "questions": [
        "Can the conclusion be supported without collecting another user's data?",
        "Have secrets, personal data, and unsupported severity claims been removed?",
        "Which reviewer and authorized private channel own the next decision?"]},
)
BY_ID = {item["id"]: item for item in PLAYBOOKS}
KINDS = {"observation", "hypothesis", "negative-result", "next-step"}
ENGINE = "hunterqa_private_research_workspace"
MAX_EVENTS = 200
SHA = re.compile(r"[a-f0-9]{64}\Z")


def _text(value):
    return isinstance(value, str) and 1 <= len(value) <= 1000 and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        return False
    try:
        return datetime.fromisoformat(value).utcoffset() is not None
    except ValueError:
        return False


def _private_create(path, payload):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def _approved_parent(path):
    raw = os.environ.get("HUNTERQA_APPROVED_ROOTS", "")
    parent = Path(path).expanduser().parent.resolve(strict=True)
    if not any(parent.is_relative_to(Path(root).expanduser().resolve(strict=True))
               for root in raw.split(os.pathsep) if root):
        raise ValueError("Workspace must be within approved local roots")
    return parent


def create_workspace(profile_path, out_dir, playbooks, *, authorized=False):
    if not authorized:
        raise PermissionError("Research initialization requires --authorized")
    _, policy_hash = _policy_snapshot(profile_path)
    if (not isinstance(playbooks, list) or not 1 <= len(playbooks) <= len(PLAYBOOKS)
            or any(not isinstance(value, str) or value not in BY_ID for value in playbooks)
            or len(set(playbooks)) != len(playbooks)):
        raise ValueError("Select unique known research playbooks")
    destination = Path(out_dir).expanduser()
    parent = _approved_parent(destination)
    if destination.name in ("", ".", "..") or destination.exists() or destination.is_symlink():
        raise ValueError("Use a new research workspace directory")
    destination = parent / destination.name
    manifest = {"schema_version": 1, "engine": ENGINE, "workspace_id": uuid.uuid4().hex,
                "policy_sha256": policy_hash, "playbooks": playbooks, "created_at": utcnow().isoformat()}
    destination.mkdir(mode=0o700)
    _private_create(destination / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    _private_create(destination / "journal.jsonl", b"")
    return manifest


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate journal field")
        result[key] = value
    return result


def read_workspace(workspace):
    directory = Path(workspace).expanduser()
    if directory.is_symlink():
        raise ValueError("Symlinked research workspace rejected")
    manifest = _read_json(directory / "manifest.json", 16_000)
    if (not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "engine", "workspace_id", "policy_sha256", "playbooks", "created_at"}
        or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
        or manifest["engine"] != ENGINE or not isinstance(manifest["workspace_id"], str)
        or not re.fullmatch(r"[a-f0-9]{32}", manifest["workspace_id"])
        or not isinstance(manifest["policy_sha256"], str) or not SHA.fullmatch(manifest["policy_sha256"])
        or not _timestamp(manifest["created_at"])):
        raise ValueError("Invalid research manifest")
    selected = manifest["playbooks"]
    if (not isinstance(selected, list) or not 1 <= len(selected) <= len(PLAYBOOKS)
            or any(not isinstance(x, str) or x not in BY_ID for x in selected)
            or len(set(selected)) != len(selected)):
        raise ValueError("Invalid research playbooks")
    raw = read_bounded(_approved_file(directory / "journal.jsonl"), 512_000)
    if raw and not raw.endswith(b"\n"):
        raise ValueError("Incomplete research journal write")
    lines = raw.splitlines()
    if len(lines) > MAX_EVENTS:
        raise ValueError("Research journal event budget exceeded")
    previous = digest(manifest)
    events = []
    for sequence, line in enumerate(lines, 1):
        event = json.loads(line, object_pairs_hook=_unique)
        if not isinstance(event, dict) or set(event) != {"sequence", "timestamp", "kind", "summary",
            "evidence_sha256", "evidence_bytes", "previous_hash", "event_hash"}:
            raise ValueError("Invalid research journal event")
        proof, size = event["evidence_sha256"], event["evidence_bytes"]
        if (type(event["sequence"]) is not int or event["sequence"] != sequence
            or not _timestamp(event["timestamp"])
            or not isinstance(event["kind"], str) or event["kind"] not in KINDS
            or not _text(event["summary"]) or event["previous_hash"] != previous
            or (proof is None and size is not None)
            or (proof is not None and (not isinstance(proof, str) or not SHA.fullmatch(proof)
                or type(size) is not int or not 0 <= size <= 2_000_000))):
            raise ValueError("Invalid research journal metadata")
        content = {k: v for k, v in event.items() if k != "event_hash"}
        if event["event_hash"] != digest(content):
            raise ValueError("Research journal hash mismatch")
        previous = event["event_hash"]
        events.append(event)
    return manifest, events, previous


def append_note(profile_path, workspace, kind, summary, *, evidence=None, authorized=False):
    if not authorized:
        raise PermissionError("Research journal changes require --authorized")
    if not isinstance(kind, str) or kind not in KINDS or not _text(summary):
        raise ValueError("Select a known note kind and a 1..1000 character single-line summary")
    _, policy_hash = _policy_snapshot(profile_path)
    manifest, _, _ = read_workspace(workspace)
    if manifest["policy_sha256"] != policy_hash:
        raise ValueError("Workspace permission profile changed; initialize a new workspace")
    directory = _approved_file(Path(workspace) / "manifest.json").parent
    lock = directory / "append.lock"
    _private_create(lock, b"An append is in progress; verify the journal before clearing a stale lock.\n")
    try:
        manifest, events, previous = read_workspace(directory)
        if manifest["policy_sha256"] != policy_hash:
            raise ValueError("Workspace permission profile changed")
        if len(events) >= MAX_EVENTS:
            raise ValueError("Research journal event budget exhausted")
        raw = read_bounded(_approved_file(evidence), 2_000_000) if evidence else None
        event = {"sequence": len(events) + 1, "timestamp": utcnow().isoformat(), "kind": kind,
                 "summary": summary, "evidence_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
                 "evidence_bytes": len(raw) if raw is not None else None, "previous_hash": previous}
        event["event_hash"] = digest(event)
        journal = _approved_file(directory / "journal.jsonl")
        fd = os.open(journal, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(event, ensure_ascii=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        return {"sequence": event["sequence"], "event_hash": event["event_hash"], "network_requests": 0}
    finally:
        lock.unlink()


def resume_workspace(workspace):
    manifest, events, last_hash = read_workspace(workspace)
    return {"schema_version": 1, "engine": "hunterqa_research_resume", "workspace_id": manifest["workspace_id"],
            "policy_sha256": manifest["policy_sha256"], "journal_head": last_hash, "event_count": len(events),
            "counts": dict(Counter(event["kind"] for event in events)),
            "playbooks": [BY_ID[key] for key in manifest["playbooks"]], "recent_notes": events[-10:],
            "network_requests": 0, "execution_resumed": False,
            "limitations": "Private operator notes and consistency checks only. Notes may contain sensitive text. "
            "Hashes are not signatures. Context resumption does not authorize or execute tests or validate a finding."}
