"""Pure boundary and traversal contracts; real Chromium checks live separately."""
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from hunterqa.browser_discovery import crawl_options, crawl_rendered
from hunterqa.bounty import BountyPolicy


@pytest.mark.parametrize("values", [(0, 1, 250), (11, 1, 250), (True, 1, 250),
    (3, -1, 250), (3, 4, 250), (3, False, 250), (3, 1, -1), (3, 1, 2001),
    (3, 1, 1.5)])
def test_crawl_bounds(values):
    with pytest.raises(ValueError):
        crawl_options(*values)


def gate():
    return SimpleNamespace(stop=False, parts=urlsplit("http://127.0.0.1:49151/app"),
        port=49151, policy=BountyPolicy.from_dict({
        "program": "Owned fixture", "platform": "local-lab",
        "authorization_reference": "Owned local fixture approval", "acknowledged_authorization": True,
        "allowed_hosts": ["127.0.0.1"], "allowed_ports": [49151], "allowed_paths": ["/app"],
        "excluded_paths": ["/app/excluded"], "methods": ["GET"], "max_requests": 20,
        "interval_seconds": 0.5, "lab_mode": True, "allow_http": True,
        "allow_private_network": True}))


class Page:
    def __init__(self, links):
        self.url = "http://127.0.0.1:49151/app"
        self.links = links
        self.navigated = []

    def evaluate(self, script):
        assert "document.querySelectorAll" in script
        return {"links": self.links, "forms": 0}

    def goto(self, url, **kwargs):
        self.navigated.append(url)
        self.url = url
        return object()


def test_crawl_filters_links_and_deduplicates_fragment_cycles():
    origin = "http://127.0.0.1:49151"
    page = Page([origin + "/app#same", origin + "/app/next", origin + "/app/next#duplicate",
        origin + "/app/excluded", origin + "/app?q=secret", "https://outside.test/",
        "http://127.0.0.1:49152/app", "javascript:void(0)", None])
    report = crawl_rendered(page, gate(), settle_ms=0)
    assert report["pages_visited"] == 2
    assert page.navigated == [origin + "/app/next"]
    assert report["links_skipped"] == 12
    assert not report["limit_reached"]
    assert "outside.test" not in str(report)


def test_crawl_reports_truncated_link_sample_and_page_limit():
    page = Page(["http://127.0.0.1:49151/app/" + str(i) for i in range(201)])
    report = crawl_rendered(page, gate(), max_pages=1, settle_ms=0)
    assert report["limit_reached"] and report["pages_visited"] == 1
    assert report["pages"][0]["observed_link_count"] == 200
    assert not page.navigated


def test_crawl_skips_same_port_different_scheme():
    page = Page(["https://127.0.0.1:49151/app/next"])
    report = crawl_rendered(page, gate(), settle_ms=0)
    assert report["links_skipped"] == 1
    assert not page.navigated


@pytest.mark.parametrize("snapshot", [None, [], {"links": []}, {"links": [], "forms": True},
    {"links": ["x"] * 202, "forms": 0}, {"links": [], "forms": 101}])
def test_invalid_snapshot_is_rejected(snapshot):
    page = Page([])
    page.evaluate = lambda _: snapshot
    with pytest.raises(RuntimeError, match="snapshot"):
        crawl_rendered(page, gate(), settle_ms=0)


def test_crawl_honors_stop_and_detects_spontaneous_navigation():
    page, request_gate = Page([]), gate()
    request_gate.stop = True
    with pytest.raises(RuntimeError, match="stopped"):
        crawl_rendered(page, request_gate, settle_ms=0)
    request_gate.stop = False
    def wait(_):
        page.url += "/changed"
    page.wait_for_timeout = wait
    with pytest.raises(RuntimeError, match="changed"):
        crawl_rendered(page, request_gate, settle_ms=1)


def test_cli_passes_explicit_browser_crawl_options(tmp_path, monkeypatch):
    from hunterqa.cli import main
    import hunterqa.browser_lab_v12 as browser
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    observed = {}
    def inspect(profile, url, **options):
        observed.update(options)
        return {"confirmed_vulnerabilities": 0}
    monkeypatch.setattr(browser, "inspect_owned_browser", inspect)
    main(["bounty-browser-lab", "--profile", str(tmp_path / "scope.json"),
          "--url", "http://127.0.0.1:49151/app", "--out", str(tmp_path / "result.json"),
          "--crawl", "--max-pages", "4", "--max-depth", "2", "--settle-ms", "150",
          "--authorized"])
    assert observed["crawl"] is True and observed["authorized"] is True
    assert (observed["max_pages"], observed["max_depth"], observed["settle_ms"]) == (4, 2, 150)
    assert (tmp_path / "result.json").exists()
