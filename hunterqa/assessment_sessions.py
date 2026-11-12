"""Encrypted app-origin test sessions. Plaintext enters memory/stdin only."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit

from .bounty import _decode_json
from .doctor import _root_is_safe
from .engagement import _expiry, utcnow
from .identity_policy import seal, unseal
from .source_files import is_linked, read_bounded

PURPOSES = {"web-session": "assessment-sessions-v1", "directory-reader": "assessment-directory-reader-v1", "aws-signing": "assessment-aws-signing-v1",
    "azure-token": "assessment-azure-token-v1", "gcp-token": "assessment-gcp-token-v1"}


def private_path(value, *, existing=True):
    root = Path(os.environ.get("HUNTERQA_ASSESSMENT_SECRET_ROOT", "")).expanduser()
    if (not root.is_absolute() or ".." in root.parts or not _root_is_safe(root) or not root.is_dir()
            or any((parent / ".git").exists() for parent in (root, *root.parents))):
        raise ValueError("Set a private assessment secret root outside Git")
    if os.name == "posix" and (root.stat().st_mode & 0o077 or root.stat().st_uid != os.geteuid()):
        raise ValueError("Assessment secret root must be owned and mode 0700")
    for segment in os.environ.get("HUNTERQA_APPROVED_ROOTS", "").split(os.pathsep):
        if segment:
            approved = Path(segment).expanduser().resolve(strict=True)
            if root.resolve().is_relative_to(approved) or approved.is_relative_to(root.resolve()):
                raise ValueError("Session secrets must be separate from assessment/source roots")
    operator = os.environ.get("HUNTERQA_OPERATOR_ROOT")
    if operator:
        control = Path(operator).expanduser().resolve()
        if root.resolve().is_relative_to(control) or control.is_relative_to(root.resolve()):
            raise ValueError("Target sessions must be separate from HunterQA identity control files")
    path = Path(value).expanduser()
    if not path.is_absolute() or path.parent != root or ".." in path.parts or is_linked(root):
        raise ValueError("Use a direct private file under the assessment secret root")
    if path.exists():
        info = path.stat(follow_symlinks=False)
        if is_linked(path) or not path.is_file() or info.st_nlink != 1 or (os.name == "posix" and (info.st_mode & 0o077 or info.st_uid != os.geteuid())):
            raise ValueError("Session files must be private regular owned files")
    elif existing:
        raise ValueError("Private session file is unavailable")
    return path


def origin(value):
    if not isinstance(value, str) or len(value) > 2048 or not value.isascii() or any(ord(c) < 33 for c in value):
        raise ValueError("Invalid app origin")
    parts = urlsplit(value)
    if (parts.scheme not in {"https", "http"} or not parts.hostname or parts.username is not None or parts.password is not None
            or parts.path or parts.query or parts.fragment or (parts.scheme == "http" and parts.hostname not in {"localhost", "127.0.0.1"})):
        raise ValueError("Sessions require a single HTTPS origin or explicit local app origin")
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise ValueError("Invalid app port")
    return value


def validate(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "expires_at", "actors"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Invalid session schema")
    if not 0 < (_expiry(data["expires_at"]) - utcnow()).total_seconds() <= 86400:
        raise ValueError("Target session authorization must expire within 24 hours")
    actors = data["actors"]
    if not isinstance(actors, dict) or not 1 <= len(actors) <= 10 or "anonymous" in actors:
        raise ValueError("Define 1..10 named actors; anonymous is reserved")
    for name, actor in actors.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name):
            raise ValueError("Invalid actor ID")
        if not isinstance(actor, dict) or set(actor) != {"origin", "headers", "cookies", "local_storage"}:
            raise ValueError("Invalid origin-bound actor state")
        origin(actor["origin"])
        headers = actor["headers"]
        if not isinstance(headers, dict) or len(headers) > 10:
            raise ValueError("Bounded actor headers required")
        if len({key.lower() for key in headers if isinstance(key, str)}) != len(headers):
            raise ValueError("Duplicate credential header names")
        for key, value in headers.items():
            if (not isinstance(key, str) or not (key in {"Authorization", "Cookie"} or re.fullmatch(r"X-[A-Za-z0-9-]{1,64}", key))
                    or not isinstance(value, str) or not 1 <= len(value) <= 16384 or not all(32 <= ord(c) < 127 for c in value)):
                raise ValueError("Unsupported actor credential header")
        if sum(len(k) + len(v) for k, v in headers.items()) > 16384:
            raise ValueError("Actor headers exceed their byte budget")
        cookies = actor["cookies"]
        if not isinstance(cookies, list) or len(cookies) > 40:
            raise ValueError("Bounded actor cookies required")
        seen = set()
        for cookie in cookies:
            if (not isinstance(cookie, dict) or set(cookie) != {"name", "value", "httpOnly", "secure", "sameSite"}
                    or not isinstance(cookie["name"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", cookie["name"])
                    or cookie["name"] in seen or not isinstance(cookie["value"], str) or not 1 <= len(cookie["value"]) <= 4096
                    or not all(33 <= ord(c) < 127 and c not in ';,"\\' for c in cookie["value"])
                    or type(cookie["httpOnly"]) is not bool or type(cookie["secure"]) is not bool
                    or cookie["sameSite"] not in {"Strict", "Lax", "None"}):
                raise ValueError("Invalid app-origin cookie")
            seen.add(cookie["name"])
            if cookie["sameSite"] == "None" and not cookie["secure"]:
                raise ValueError("SameSite=None requires a Secure cookie")
        storage = actor["local_storage"]
        if sum(len(row["name"]) + len(row["value"]) for row in cookies) > 16384:
            raise ValueError("Actor cookies exceed their byte budget")
        if (not isinstance(storage, dict) or len(storage) > 40 or any(not isinstance(key, str) or not 1 <= len(key) <= 128
                or not isinstance(value, str) or len(value) > 16384 for key, value in storage.items())):
            raise ValueError("Invalid app local storage")
    return data


def create(output, key_file, raw, *, authorized=False, purpose="web-session"):
    if authorized is not True:
        raise PermissionError("Session creation requires --authorized")
    if purpose not in PURPOSES:
        raise ValueError("Unsupported assessment credential purpose")
    if not isinstance(raw, bytes) or len(raw) > 262144:
        raise ValueError("Bounded session JSON required through stdin")
    data = validate(_decode_json(raw))
    destination, key_path = private_path(output, existing=False), private_path(key_file, existing=False)
    if destination == key_path or destination.exists():
        raise FileExistsError("Choose a new encrypted session file")
    if key_path.exists():
        key = read_bounded(key_path, 128).decode("ascii").strip()
    else:
        key = secrets.token_hex(32)
        fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(key + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    if not re.fullmatch(r"[a-f0-9]{64}", key):
        raise ValueError("Invalid session encryption key")
    encrypted = {"schema_version": 1, "ciphertext": seal(key, PURPOSES[purpose], data)}
    if purpose != "web-session":
        encrypted["purpose"] = purpose
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(encrypted) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {"created": True, "actors": sorted(data["actors"]), "secrets_displayed": False}


def load_document(input_file, key_file, *, purpose="web-session"):
    if purpose not in PURPOSES:
        raise ValueError("Unsupported assessment credential purpose")
    path, key_path = private_path(input_file), private_path(key_file)
    if path == key_path:
        raise ValueError("Use separate session and key files")
    raw = read_bounded(path, 524288)
    key = read_bounded(key_path, 128).decode("ascii").strip()
    if not re.fullmatch(r"[a-f0-9]{64}", key):
        raise ValueError("Invalid session key")
    wrapper = _decode_json(raw)
    expected = {"schema_version", "ciphertext"} | ({"purpose"} if purpose != "web-session" else set())
    if (not isinstance(wrapper, dict) or set(wrapper) != expected or wrapper.get("purpose", "web-session") != purpose or type(wrapper["schema_version"]) is not int
            or wrapper["schema_version"] != 1 or not isinstance(wrapper["ciphertext"], str)):
        raise ValueError("Invalid encrypted session wrapper")
    data = validate(unseal(key, PURPOSES[purpose], wrapper["ciphertext"]))
    return data, hashlib.sha256(raw + hashlib.sha256(key.encode()).digest()).hexdigest()


def load(input_file, key_file, *, purpose="web-session"):
    data, fingerprint = load_document(input_file, key_file, purpose=purpose)
    return data["actors"], fingerprint


def create_cli(output, key_file, *, authorized=False, purpose="web-session"):
    import sys
    if authorized is not True:
        raise PermissionError("Session creation requires --authorized")
    return create(output, key_file, sys.stdin.buffer.read(262145), authorized=True, purpose=purpose)
