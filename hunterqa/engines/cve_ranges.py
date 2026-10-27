"""Strict, bounded OSV version-range evaluation; no remote lookups.

PyPI ECOSYSTEM intervals use PEP 440, SEMVER intervals use SemVer 2.0.0.
Unrecognized ecosystem/range/event or invalid input => UNKNOWN, never a
negative security assertion. Explicit affected.versions is always supported.
"""
from __future__ import annotations

import re
from packaging.version import InvalidVersion, Version

SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$",
    re.ASCII,
)


def _semver(value: str):
    match = SEMVER.fullmatch(value)
    if not match:
        raise ValueError("Not strict SemVer")
    major, minor, patch, prerelease, _build = match.groups()
    parts = ()
    if prerelease:
        items = prerelease.split(".")
        if any(not item or (item.isdigit() and len(item) > 1 and item.startswith("0"))
               for item in items):
            raise ValueError("Invalid prerelease")
        parts = tuple((0, int(p)) if p.isdigit() else (1, p) for p in items)
    return (int(major), int(minor), int(patch), parts)


def _cmp_semver(left: str, right: str) -> int:
    a = _semver(left)
    b = _semver(right)
    if a[:3] != b[:3]:
        return (a[:3] > b[:3]) - (a[:3] < b[:3])
    ap, bp = a[3], b[3]
    if not ap and not bp:
        return 0
    if not ap:
        return 1
    if not bp:
        return -1
    for x, y in zip(ap, bp):
        if x != y:
            return (x > y) - (x < y)
    return (len(ap) > len(bp)) - (len(ap) < len(bp))


def _cmp_pypi(left: str, right: str) -> int:
    a, b = Version(left), Version(right)
    return (a > b) - (a < b)


def range_affected(version: str, ecosystem: str, entry: dict) -> str:
    """Return 'affected', 'not_listed', or 'unknown'.

    not_listed means *this one range* did not include the version. It does
    not establish absence of any other advisory or undocumented vulnerability.
    """
    if not isinstance(entry, dict) or not isinstance(version, str) or len(version) > 120:
        return "unknown"
    rtype = entry.get("type")
    if rtype == "SEMVER":
        compare = _cmp_semver
    elif rtype == "ECOSYSTEM" and ecosystem == "PyPI":
        compare = _cmp_pypi
    else:
        return "unknown"
    events = entry.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= 100:
        return "unknown"
    intervals = []
    start = None
    try:
        compare(version, version)
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                return "unknown"
            key, value = next(iter(event.items()))
            if key not in {"introduced", "fixed", "last_affected", "limit"}:
                return "unknown"
            if not isinstance(value, str) or not value or len(value) > 120:
                return "unknown"
            if key == "introduced":
                if start is not None:
                    return "unknown"
                if value != "0":
                    compare(value, value)
                start = value
            else:
                if start is None:
                    return "unknown"
                if value != "*" or key != "limit":
                    compare(value, value)
                    if start != "0" and compare(start, value) > 0:
                        return "unknown"
                intervals.append((start, key, value))
                start = None
        if start is not None:
            intervals.append((start, "limit", "*"))
        if not intervals:
            return "unknown"
        for low, end_kind, high in intervals:
            starts = low == "0" or compare(version, low) >= 0
            if end_kind == "limit" and high == "*":
                ends = True
            elif end_kind == "last_affected":
                ends = compare(version, high) <= 0
            else:
                ends = compare(version, high) < 0
            if starts and ends:
                return "affected"
        return "not_listed"
    except (ValueError, InvalidVersion, TypeError, OverflowError):
        return "unknown"


def affected_entry(version: str, ecosystem: str, affected: dict) -> tuple[bool, str, bool]:
    """(matches, method, unsupported_range_present)."""
    enumerated = affected.get("versions")
    if isinstance(enumerated, list) and len(enumerated) <= 3000:
        if version in enumerated:
            return True, "OSV affected.versions", False
    ranges = affected.get("ranges") or []
    if not isinstance(ranges, list) or len(ranges) > 100:
        return False, "", True
    unknown = False
    for rng in ranges:
        status = range_affected(version, ecosystem, rng)
        if status == "affected":
            return True, f"OSV {rng['type']} interval", unknown
        if status == "unknown":
            unknown = True
    return False, "", unknown
