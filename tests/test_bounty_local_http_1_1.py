"""Integration tests use ONLY an ephemeral localhost server owned by the test."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from hunterqa.bounty import BountyPolicy, assess, read_only_probe


class Handler(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *args):
        pass

    def do_HEAD(self):
        Handler.hits.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/out-of-scope")
        else:
            self.send_response(200)
            self.send_header("Set-Cookie", "session=hidden-secret; HttpOnly")
        self.end_headers()

    def do_GET(self):
        Handler.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>Owned local test page</html>")


def test_pinned_loopback_http_no_redirect_and_no_cookie_storage(tmp_path, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Handler.hits = []
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        profile = {
            "program": "Local integration server", "platform": "local-lab",
            "authorization_reference": "Isolated automated test server",
            "acknowledged_authorization": True,
            "allowed_hosts": ["127.0.0.1"], "allowed_ports": [port],
            "allowed_paths": ["/"], "methods": ["HEAD", "GET"],
            "lab_mode": True, "allow_http": True,
            "allow_private_network": True, "max_requests": 2,
            "interval_seconds": 0.5,
        }
        policy = BountyPolicy.from_dict(profile)
        direct = read_only_probe(policy, f"http://127.0.0.1:{port}/redirect")
        assert direct["status"] == 302
        assert Handler.hits == ["/redirect"]  # the redirect was NOT followed

        monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
        p = tmp_path / "policy.json"
        import json
        p.write_text(json.dumps(profile))
        urls = tmp_path / "targets.txt"
        urls.write_text(f"http://127.0.0.1:{port}/view\n")
        report = assess(p, urls, authorized=True, method="GET")
        assert report["observations"][0]["status"] == 200
        assert report["observations"][0]["body_sha256"] is not None
        assert report["claims"]["confirmed_zero_days"] == 0
        assert Handler.hits == ["/redirect", "/view"]
        assert "hidden-secret" not in json.dumps(report)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
