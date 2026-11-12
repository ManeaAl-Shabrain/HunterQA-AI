"""Bounded native GPO file analysis. Never applies policies or resolves identities."""
import hashlib
import re
import struct

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 524288
MODES = {"gpo-security-template", "gpo-machine-registry"}
RULE_VERSION = "gpo-file-rules-1"
_BROAD = {"S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545"}
_PRIVILEGES = {"sedebugprivilege", "sebackupprivilege", "serestoreprivilege", "setakeownershipprivilege",
    "seloaddriverprivilege", "seimpersonateprivilege", "setcbprivilege", "secreatetokenprivilege"}
# Only machine-scoped inputs are admitted. Paths/values are matched, never exported.
_REGISTRY = {
    (r"system\currentcontrolset\control\lsa", "lmcompatibilitylevel"): ("legacy-authentication", lambda v: v < 3, 5),
    (r"system\currentcontrolset\services\lanmanserver\parameters", "requiresecuritysignature"): ("smb-signing-not-required", lambda v: v == 0, 1),
    (r"system\currentcontrolset\services\ldap", "ldapclientintegrity"): ("ldap-client-signing-disabled", lambda v: v == 0, 2),
    (r"system\currentcontrolset\control\securityproviders\wdigest", "uselogoncredential"): ("wdigest-credential-storage", lambda v: v == 1, 1),
}


def _template(raw):
    if not raw.startswith(b"\xff\xfe") or len(raw) % 2:
        raise ValueError("Use the original UTF-16LE BOM security template")
    try:
        text = raw[2:].decode("utf-16-le")
    except UnicodeError:
        raise ValueError("Invalid security-template encoding") from None
    if "\x00" in text or re.search(r"(?<!\r)\n|\r(?!\n)", text):
        raise ValueError("Preserve original security-template CRLF lines")
    lines = text.split("\r\n")
    if len(lines) > 4000 or any(len(line) > 8192 for line in lines):
        raise ValueError("Security template exceeds parsing limits")
    section, sections, seen, rows, unsupported = None, set(), set(), [], 0
    for number, line in enumerate(lines, 1):
        value = line.strip()
        if not value or value.startswith(";"):
            continue
        if value.startswith("[") and value.endswith("]"):
            section = value[1:-1].strip().casefold()
            if not section or section in sections:
                raise ValueError("Ambiguous security-template sections")
            sections.add(section)
            continue
        if section is None:
            raise ValueError("Security-template section required")
        if section not in {"version", "unicode", "system access", "privilege rights", "registry values"}:
            unsupported += 1
            continue
        if "=" not in value:
            raise ValueError("Invalid selected security-template directive")
        key, value = (part.strip() for part in value.split("=", 1))
        identity = (section, key.casefold())
        if not key or identity in seen:
            raise ValueError("Ambiguous security-template directive")
        seen.add(identity)
        rows.append((section, key.casefold(), value, number))
        if len(rows) > 1000:
            raise ValueError("Too many security-template directives")
    header = {(section, key): value for section, key, value, _ in rows}
    if (header.get(("version", "signature"), "").casefold() != '"$chicago$"'
            or header.get(("version", "revision")) != "1"
            or ("unicode" in sections and header.get(("unicode", "unicode"), "").casefold() != "yes")):
        raise ValueError("Unsupported security-template version")
    return rows, unsupported


def _registry(raw):
    if raw[:8] != b"PReg\x01\x00\x00\x00":
        raise ValueError("Unsupported registry policy signature/version")
    offset, rows, special = 8, [], 0

    def take(size):
        nonlocal offset
        end = offset + size
        if end > len(raw):
            raise ValueError("Truncated registry policy")
        result, offset = raw[offset:end], end
        return result

    def mark(value):
        if take(2) != value.encode("utf-16-le"):
            raise ValueError("Invalid registry policy delimiter")

    def string(maximum):
        chars = bytearray()
        for _ in range(maximum + 1):
            pair = take(2)
            if pair == b"\x00\x00":
                try:
                    return chars.decode("utf-16-le")
                except UnicodeError:
                    raise ValueError("Invalid registry policy identifier") from None
            chars.extend(pair)
        raise ValueError("Registry policy identifier exceeds limits")

    while offset < len(raw):
        start = offset
        mark("[")
        key = string(4096)
        mark(";")
        name = string(259)
        mark(";")
        kind = struct.unpack("<I", take(4))[0]
        mark(";")
        size = struct.unpack("<I", take(4))[0]
        if kind not in {1, 2, 3, 4, 5, 7, 11} or size > 65535 or not key or not name:
            raise ValueError("Unsupported registry policy record")
        mark(";")
        data = take(size)
        mark("]")
        if kind in {4, 5, 11} and size != (8 if kind == 11 else 4):
            raise ValueError("Invalid numeric registry policy size")
        if name.startswith("**"):
            special += 1
        rows.append((key.casefold(), name.casefold(), kind, data, start))
        if len(rows) > 1000:
            raise ValueError("Too many registry policy instructions")
    return rows, special


def review_bytes(raw, *, mode):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES or mode not in MODES:
        raise ValueError("Select a supported bounded native GPO format")
    findings, observations = [], []
    unsupported, overwritten, unresolved_identities = 0, 0, 0

    def observe(key, matched, ordinal, *, cwe="CWE-16", severity="WARNING", unresolved=False):
        observations.append({"rule_id": "gpo." + key, "record": ordinal,
            "state": "review-candidate" if matched else "insufficient-evidence" if unresolved else "no-selected-cue"})
        if matched:
            findings.append({"rule_id": "gpo." + key, "title": "Review supplied GPO directive: " + key.replace("-", " "),
                "severity": severity, "cwe": cwe, "file_path": "external-evidence", "line_start": 1,
                "test_case": "record-" + str(ordinal), "verification_status": "unverified",
                "remediation": "Verify intended policy and resultant settings on approved systems. Restrict privileged rights and legacy credential/protocol settings; test compatibility before changing the GPO."})

    registry = []
    if mode == "gpo-security-template":
        rows, unsupported = _template(raw)
        for section, key, value, number in rows:
            if section in {"unicode", "version"}:
                continue
            if section == "system access" and key in {"minimumpasswordlength", "passwordcomplexity", "cleartextpassword", "lockoutbadcount", "enableguestaccount"}:
                if not re.fullmatch(r"[0-9]{1,5}", value) or int(value) > 65535:
                    raise ValueError("Invalid selected security-template integer")
                number_value = int(value)
                if key in {"passwordcomplexity", "cleartextpassword", "enableguestaccount"} and number_value not in {0, 1}:
                    raise ValueError("Invalid selected security-template boolean")
                rule, match, severity = {
                    "minimumpasswordlength": ("password-length-below-eight", number_value < 8, "WARNING"),
                    "passwordcomplexity": ("complexity-disabled-review", number_value == 0, "INFO"),
                    "cleartextpassword": ("reversible-password-storage", number_value == 1, "WARNING"),
                    "lockoutbadcount": ("lockout-disabled-review", number_value == 0, "INFO"),
                    "enableguestaccount": ("guest-enabled-review", number_value == 1, "INFO"),
                }[key]
                observe(rule, match, number, severity=severity, cwe="CWE-256" if key == "cleartextpassword" else "CWE-521" if key == "minimumpasswordlength" else "CWE-16")
            elif section == "privilege rights" and key in _PRIVILEGES:
                identities = [v.strip().removeprefix("*") for v in value.split(",")] if value else []
                if len(identities) > 200:
                    raise ValueError("Too many privilege identities")
                unresolved = sum(not re.fullmatch(r"S-1-(?:[0-9]{1,10}-){1,15}[0-9]{1,10}", identity) for identity in identities)
                unsupported += int(bool(unresolved))
                unresolved_identities += unresolved
                observe("broad-sensitive-privilege", bool(set(identities) & _BROAD), number, cwe="CWE-269", unresolved=bool(unresolved))
            elif section == "registry values" and key.startswith("machine\\") and "\\" in key[8:]:
                path, name = key[8:].rsplit("\\", 1)
                if (path, name) not in _REGISTRY:
                    unsupported += 1
                    continue
                if not re.fullmatch(r"4\s*,\s*[0-9]{1,10}", value) or int(value.split(",")[1]) > 0xffffffff:
                    raise ValueError("Expected selected DWORD security-template directive")
                registry.append((path, name, 4, struct.pack("<I", int(value.split(",")[1])), number))
            else:
                unsupported += 1
        ambiguous = False
    else:
        rows, special = _registry(raw)
        # Unknown deletion/ACL programs are not interpreted as simple assignments.
        ambiguous = bool(special)
        unsupported += special
        registry = rows
    final = {}
    for path, name, kind, data, ordinal in registry:
        if (path, name) not in _REGISTRY:
            if not name.startswith("**"):
                unsupported += 1
            continue
        if (path, name) in final:
            overwritten += 1
        final[path, name] = (kind, data, ordinal)
    for identity, (kind, data, ordinal) in final.items():
        if ambiguous or kind not in {4, 5}:
            unsupported += 1
            continue
        rule, predicate, maximum = _REGISTRY[identity]
        value = int.from_bytes(data, "little" if kind == 4 else "big")
        if value > maximum:
            unsupported += 1
            continue
        observe(rule, predicate(value), ordinal)
    return {"engine": "native-gpo-file-review", "schema_version": 1, "rule_version": RULE_VERSION,
        "input_sha256": hashlib.sha256(raw).hexdigest(), "input_mode": mode,
        "findings": findings, "observations": observations, "selected_directives_reviewed": len(observations),
        "unsupported_directives": unsupported, "overwritten_registry_assignments": overwritten,
        "unresolved_identity_references": unresolved_identities,
        "registry_program_requires_review": ambiguous, "effective_policy_verified": False,
        "network_requests": 0, "external_tools_executed": 0,
        "limitations": ["Supplied machine-scoped file directives only; no SYSVOL collection, Windows policy application or verified provenance",
            "No GPO links, precedence across files, security/WMI filters, inheritance, resultant policy or effective privilege resolution",
            "Unsupported directives and unresolved identities remain unassessed; absent findings do not establish security",
            "Password and lockout cues require context; no claim of complete password-policy compliance",
            "Registry special/deletion programs disable scalar evaluation; repeated ordinary assignments use file order only"]}


def review_file(path, *, authorized=False, mode):
    if authorized is not True:
        raise PermissionError("Native GPO review requires explicit authorization")
    return review_bytes(read_bounded(_approved_file(path), MAX_BYTES), mode=mode)
