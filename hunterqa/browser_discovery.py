"""Bounded rendered-link discovery inside the existing owned-loopback browser."""
from collections import deque
import hashlib
from urllib.parse import urldefrag

from .browser_lab_v12 import preflight_lab_browser


def crawl_options(max_pages, max_depth, settle_ms):
    for value, lower, upper in ((max_pages, 1, 10), (max_depth, 0, 3), (settle_ms, 0, 2000)):
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError("Invalid owned browser crawl bounds")


def _candidate(gate, url):
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("Invalid rendered link")
    clean = urldefrag(url)[0]
    parts, port = preflight_lab_browser(gate.policy, clean)
    if parts.scheme != gate.parts.scheme or port != gate.port:
        raise ValueError("Rendered link is outside the original browser origin")
    return clean


def crawl_rendered(page, gate, *, max_pages=3, max_depth=1, settle_ms=250):
    """Use the already guarded ephemeral context, including its optional login.

    Read rendered anchors only; never click application actions or submit forms.
    Hashes are private evidence references, not proof of authentication or safety.
    """
    crawl_options(max_pages, max_depth, settle_ms)
    initial = _candidate(gate, page.url)
    frontier, seen = deque([(initial, 0)]), {initial}
    rows, skipped, bounded = [], 0, False
    while frontier and len(rows) < max_pages:
        if gate.stop:
            raise RuntimeError("Owned browser crawl stopped by request guard")
        url, depth = frontier.popleft()
        if rows:
            response = page.goto(url, wait_until="domcontentloaded", timeout=12_000)
            if response is None or gate.stop:
                raise RuntimeError("Owned browser crawl navigation denied")
        if settle_ms:
            page.wait_for_timeout(settle_ms)
        if gate.stop:
            raise RuntimeError("Owned browser crawl stopped during rendering")
        current = _candidate(gate, page.url)
        # A page may navigate itself. Do not attribute its links to another page.
        if current != url:
            raise RuntimeError("Owned browser page changed during discovery")
        snapshot = page.evaluate("""() => ({
            links: Array.from(document.querySelectorAll('a[href]')).slice(0, 201)
                .map(a => a.href.length <= 2048 ? a.href : null),
            forms: Math.min(100, document.querySelectorAll('form').length)
        })""")
        if (not isinstance(snapshot, dict) or set(snapshot) != {"links", "forms"}
                or not isinstance(snapshot["links"], list) or len(snapshot["links"]) > 201
                or type(snapshot["forms"]) is not int or not 0 <= snapshot["forms"] <= 100):
            raise RuntimeError("Invalid owned browser discovery snapshot")
        links = snapshot["links"]
        bounded |= len(links) > 200
        rows.append({"url_sha256": hashlib.sha256(current.encode()).hexdigest(),
                     "depth": depth, "form_count": snapshot["forms"],
                     "observed_link_count": min(200, len(links))})
        for link in links[:200]:
            try:
                candidate = _candidate(gate, link)
            except (ValueError, TypeError):
                skipped += 1
                continue
            if candidate in seen:
                continue
            if depth >= max_depth or len(seen) >= 200:
                bounded = True
                skipped += 1
                continue
            seen.add(candidate)
            frontier.append((candidate, depth + 1))
    return {"mode": "owned-loopback-rendered-anchors", "pages": rows,
            "pages_visited": len(rows), "max_pages": max_pages, "max_depth": max_depth,
            "settle_ms": settle_ms, "links_skipped": skipped,
            "limit_reached": bool(frontier) or bounded, "forms_submitted_by_crawler": 0,
            "session": "existing_ephemeral_context", "coverage_complete": False,
            "authentication_verified": False, "exploitability_verified": False}
