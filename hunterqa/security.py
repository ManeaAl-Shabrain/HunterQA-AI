from __future__ import annotations

import hmac
import os
from pathlib import Path

from flask import current_app, session


AUTHORIZATION_TEXT = "I AM AUTHORIZED TO SCAN THIS PROJECT"


def approved_roots() -> list[Path]:
    raw = current_app.config.get("APPROVED_ROOTS", "")
    items = raw if isinstance(raw, (list, tuple)) else raw.split(os.pathsep)
    return [Path(item).expanduser().resolve() for item in items if str(item).strip()]


def validate_project_path(value: str) -> Path:
    if current_app.config.get("OPERATOR_DATABASE"):
        from .operator_store import validate_separation
        validate_separation(current_app.config.get("APPROVED_ROOTS", ""))
    if not value or "\x00" in value:
        raise ValueError("Enter a local project directory.")
    candidate = Path(value).expanduser().resolve(strict=True)
    if not candidate.is_dir():
        raise ValueError("The project path must be a directory.")
    roots = approved_roots()
    if not roots:
        raise ValueError("No approved roots are configured. Set HUNTERQA_APPROVED_ROOTS first.")
    if not any(candidate == root or candidate.is_relative_to(root) for root in roots):
        raise ValueError("That directory is outside the approved project roots.")
    return candidate


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = os.urandom(24).hex()
        session["csrf_token"] = token
    return token


def valid_csrf(value: str | None) -> bool:
    expected = session.get("csrf_token", "")
    return bool(isinstance(value, str) and isinstance(expected, str) and value and expected
                and len(value) <= 256
                and hmac.compare_digest(value.encode("utf-8"), expected.encode("utf-8")))

