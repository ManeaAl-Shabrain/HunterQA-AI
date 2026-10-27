"""Evidence identifiers and deliberately conservative crash correlation."""
from __future__ import annotations
import hashlib
import re
from typing import Any

_HASH = re.compile(r"^[0-9a-f]{64}$")


def evidence_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_HASH.fullmatch(value.lower()))


def correlate_evidence(crashes: list[dict], diagnostics: list[dict]) -> list[dict]:
    """Require BOTH crash input hash and binary hash to link sanitizer evidence.

    A shared input hash alone cannot prove a diagnostic came from the same build.
    Even a matched pair is a provenance link, not vulnerability validation.
    """
    results = []
    for crash in crashes:
        matched = []
        candidates = 0
        input_hash = crash.get("sha256")
        binary_hash = crash.get("binary_sha256")
        for diagnostic in diagnostics:
            other_input = diagnostic.get("input_sha256")
            other_binary = diagnostic.get("binary_sha256")
            if not (valid_sha256(input_hash) and valid_sha256(other_input)):
                continue
            if input_hash.lower() != other_input.lower():
                continue
            if (valid_sha256(binary_hash) and valid_sha256(other_binary)
                    and binary_hash.lower() == other_binary.lower()):
                matched.append(diagnostic)
            else:
                candidates += 1
        results.append({
            "crash": crash,
            "matched_diagnostics": matched,
            "correlation_status": (
                "matched_input_and_binary" if matched
                else "same_input_unverified_build" if candidates
                else "not_established"
            ),
            "candidate_diagnostics_count": candidates,
            "requires_human_review": True,
            "zero_day_confirmed": False,
        })
    return results
