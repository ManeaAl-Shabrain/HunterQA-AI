"""Real loopback transport privacy tests; no Ollama or external service needed."""
import json
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hunterqa import local_ai


@pytest.fixture
def server(monkeypatch):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            requests.append((self.path, self.rfile.read(int(self.headers["Content-Length"]))))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/trap")
                self.end_headers()
                return
            body = b"x" * 1000 if self.path == "/large" else b'{"response":"local answer"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            requests.append((self.path, b""))
            self.send_response(200)
            self.end_headers()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd, requests
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def test_model_request_ignores_proxy_environment(server, monkeypatch):
    httpd, requests = server
    endpoint = f"http://127.0.0.1:{httpd.server_port}/api/generate"
    monkeypatch.setattr(local_ai, "GENERATE_URL", endpoint)
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    result = local_ai.generate({"prompt": "private local source"}, endpoint=endpoint)
    assert result["response"] == "local answer"
    assert len(requests) == 1
    assert json.loads(requests[0][1])["prompt"] == "private local source"


def test_model_redirect_never_reaches_second_endpoint(server, monkeypatch):
    httpd, requests = server
    endpoint = f"http://127.0.0.1:{httpd.server_port}/redirect"
    monkeypatch.setattr(local_ai, "GENERATE_URL", endpoint)
    with pytest.raises(urllib.error.HTTPError):
        local_ai.generate({"prompt": "private"}, endpoint=endpoint)
    assert [path for path, _ in requests] == ["/redirect"]


def test_model_response_is_bounded(server, monkeypatch):
    httpd, _ = server
    endpoint = f"http://127.0.0.1:{httpd.server_port}/large"
    monkeypatch.setattr(local_ai, "GENERATE_URL", endpoint)
    with pytest.raises(ValueError, match="response exceeds"):
        local_ai.generate({}, endpoint=endpoint, max_response=50)


@pytest.mark.parametrize("endpoint", ["https://example.test/api/generate", "file:///tmp/private",
                                      "http://localhost:11434/api/generate", local_ai.GENERATE_URL + "?x=1"])
def test_model_rejects_nonexact_destination_without_network(endpoint, monkeypatch):
    monkeypatch.setattr(local_ai.urllib.request, "build_opener", lambda *a: pytest.fail("Network setup"))
    with pytest.raises(ValueError, match="fixed loopback"):
        local_ai.generate({}, endpoint=endpoint)


def test_scanner_falls_back_on_invalid_or_oversized_model_output(app, monkeypatch):
    from hunterqa.scanner import ScanService
    monkeypatch.setattr("hunterqa.scanner.generate", lambda *a, **kw: (_ for _ in ()).throw(ValueError("private data")))
    report = ScanService(app)._create_report([])
    assert "unverified findings" in report
    assert "private data" not in report
