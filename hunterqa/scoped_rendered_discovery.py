"""Rendered anchor inventory and reference scoring; no browser-owned transport."""
import asyncio
from collections import deque
import hashlib
import re
from urllib.parse import urldefrag


def validate_hash_routes(values):
    if (not isinstance(values, list) or not 1 <= len(values) <= 10
            or any(not isinstance(v, str) or not 1 <= len(v) <= 256
                   or re.fullmatch(r"/(?:[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*/?)?", v) is None for v in values)
            or len(set(values)) != len(values)):
        raise ValueError("Define 1..10 unique exact slash hash routes; no queries, encoding or traversal")


def validate_options(options):
    required = {"max_pages", "max_depth", "settle_ms"}
    if not isinstance(options, dict) or set(options) not in (required, required | {"hash_routes"}):
        raise ValueError("Explicit rendered discovery bounds required")
    for key, lower, upper in (("max_pages", 1, 10), ("max_depth", 0, 3), ("settle_ms", 0, 2000)):
        if type(options[key]) is not int or not lower <= options[key] <= upper:
            raise ValueError("Invalid rendered discovery bound")
    if "hash_routes" in options:
        validate_hash_routes(options["hash_routes"])


def candidate(policy, start, url, *, hash_routes=()):
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("Invalid rendered URL")
    clean, fragment = urldefrag(url)
    parts, host, port, _ = policy.authorize_url(clean, "GET")
    origin, origin_host, origin_port, _ = policy.authorize_url(start, "GET")
    if (parts.scheme, host, port) != (origin.scheme, origin_host, origin_port) or parts.scheme != "https":
        raise ValueError("Rendered URL outside original HTTPS origin")
    if hash_routes:
        validate_hash_routes(hash_routes)
        if fragment:
            if (parts.path or "/") != (origin.path or "/") or fragment not in hash_routes:
                raise ValueError("Hash route outside explicit start-document selection")
            return clean + "#" + fragment
    return clean


def url_hash(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


async def crawl(page, policy, step, gate):
    """Only navigate anchors; all network admission stays in the context route.

    The supplied page reuses an ephemeral cookie jar from the optional single
    login. No clicks, submissions, DOM or session exports are performed here.
    """
    options = step["discovery"]
    validate_options(options)
    routes = options.get("hash_routes", [])
    def admitted(url):
        return candidate(policy, step["url"], url, hash_routes=routes)
    initial = admitted(page.url)
    frontier, queued, discovered = deque([(initial, 0)]), {initial}, {initial}
    rows, skipped, truncated, hash_states = [], 0, False, 0
    while frontier and len(rows) < options["max_pages"]:
        gate.check()
        url, depth = frontier.popleft()
        navigation_kind = "initial-document"
        if rows:
            previous = admitted(page.url)
            hash_transition = bool(routes) and previous != url and urldefrag(previous)[0] == urldefrag(url)[0]
            response = await page.goto(url, wait_until="domcontentloaded", timeout=12_000)
            if response is None and not hash_transition:
                raise RuntimeError("Rendered navigation returned no response")
            navigation_kind = "same-document-fragment" if response is None else "document"
        gate.check()
        if options["settle_ms"]:
            await page.wait_for_timeout(options["settle_ms"])
        gate.check()
        if admitted(page.url) != url:
            raise RuntimeError("Page changed during rendered discovery")
        snapshot = await asyncio.wait_for(page.evaluate("""() => ({
            links: Array.from(document.querySelectorAll('a[href]')).slice(0, 201)
                .map(a => a.href.length <= 2048 ? a.href : null),
            forms: Math.min(100, document.querySelectorAll('form').length)
        })"""), timeout=3)
        gate.check()
        if admitted(page.url) != url:
            raise RuntimeError("Page changed during rendered discovery snapshot")
        if (not isinstance(snapshot, dict) or set(snapshot) != {"links", "forms"}
                or not isinstance(snapshot["links"], list) or len(snapshot["links"]) > 201
                or type(snapshot["forms"]) is not int or not 0 <= snapshot["forms"] <= 100):
            raise RuntimeError("Invalid rendered discovery snapshot")
        links = snapshot["links"]
        truncated |= len(links) > 200
        rows.append({"url_sha256": url_hash(url), "depth": depth,
                     "form_count": snapshot["forms"], "observed_link_count": min(200, len(links)),
                     "navigation_kind": navigation_kind})
        hash_states += bool(urldefrag(url)[1])
        for link in links[:200]:
            try:
                target = admitted(link)
            except (ValueError, TypeError):
                skipped += 1
                continue
            if target not in discovered and len(discovered) >= 200:
                truncated = True
                skipped += 1
                continue
            discovered.add(target)
            if target in queued:
                continue
            if depth >= options["max_depth"]:
                truncated = True
                continue
            queued.add(target)
            frontier.append((target, depth + 1))
    return {"mode": "scoped-https-rendered-anchors",
            **{k: options[k] for k in ("max_pages", "max_depth", "settle_ms")},
            "hash_routes_selected": len(routes), "hash_states_visited": hash_states,
            "pages": rows, "pages_visited": len(rows),
            "discovered_url_sha256": sorted(url_hash(url) for url in discovered),
            "links_skipped": skipped, "limit_reached": bool(frontier) or truncated,
            "forms_submitted_by_crawler": 0, "coverage_complete": False,
            "authentication_verified": False, "session": "ephemeral_no_storage_export"}


def measure(report, reference):
    """Score only against an operator-supplied reference, never field coverage."""
    if (not isinstance(reference, dict) or set(reference) != {"schema_version", "expected_url_sha256"}
            or type(reference["schema_version"]) is not int or reference["schema_version"] != 1):
        raise ValueError("Invalid discovery reference schema")
    def hashes(values):
        if (not isinstance(values, list) or not 1 <= len(values) <= 1000
                or any(not isinstance(v, str) or re.fullmatch(r"[0-9a-f]{64}", v) is None for v in values)
                or len(set(values)) != len(values)):
            raise ValueError("Expected unique bounded SHA-256 URL references")
        return set(values)
    expected = hashes(reference["expected_url_sha256"])
    if not isinstance(report, dict) or report.get("engine") != "hunterqa_approved_assessment":
        raise ValueError("Expected an engagement report")
    observations = report.get("observations")
    if not isinstance(observations, list) or len(observations) != 1:
        raise ValueError("Expected one rendered discovery observation")
    observation = observations[0]
    if not isinstance(observation, dict) or observation.get("mode") != "browser-discovery":
        raise ValueError("Expected browser-discovery observation")
    discovery = observation.get("discovery")
    if not isinstance(discovery, dict) or discovery.get("mode") != "scoped-https-rendered-anchors":
        raise ValueError("Missing completed discovery inventory")
    observed = hashes(discovery.get("discovered_url_sha256"))
    pages = discovery.get("pages")
    visited = None
    if pages is not None:
        if (not isinstance(pages, list) or not 1 <= len(pages) <= 10
                or any(not isinstance(p, dict) for p in pages)):
            raise ValueError("Invalid retained discovery page observations")
        visited = hashes([p.get("url_sha256") for p in pages])
        if not visited <= observed:
            raise ValueError("Visited pages must be present in the discovered inventory")
    return {"engine": "hunterqa_discovery_reference_coverage", "schema_version": 1,
            "reference_count": len(expected), "discovered_count": len(observed),
            "reference_matches": len(expected & observed), "reference_missing": len(expected - observed),
            "unlabelled_discovered": len(observed - expected),
            "reference_discovery_recall": len(expected & observed) / len(expected),
            "visited_count": len(visited) if visited is not None else None,
            "visited_reference_matches": len(expected & visited) if visited is not None else None,
            "visited_reference_missing": len(expected - visited) if visited is not None else None,
            "reference_visit_recall": len(expected & visited) / len(expected) if visited is not None else None,
            "run_stopped": report.get("stopped") is not False,
            "coverage_complete": False, "reference_authenticity": "unverified",
            "network_requests": 0,
            "limitations": "Supplied reference only. Unlabelled URLs are not false positives; "
                           "Visits count retained page/state observations, not successful endpoint or authentication verification. "
                           "Legacy inventories without page rows have unknown visit metrics; "
                           "an incomplete reference cannot establish endpoint completeness or vulnerability accuracy."}
