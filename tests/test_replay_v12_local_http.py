"""Real HEAD network smoke against only our own short-lived loopback test server."""
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from hunterqa.replay_v12 import replay_har_head


class HeadOnlyHandler(BaseHTTPRequestHandler):
    received = []

    def log_message(self, *args):
        pass

    def do_HEAD(self):
        type(self).received.append({
            "method": "HEAD", "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "cookie": self.headers.get("Cookie"),
            "content_length": self.headers.get("Content-Length"),
        })
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "private-secret=never-exported")
        self.end_headers()

    def do_GET(self):
        type(self).received.append({"method": "GET"})
        self.send_error(405)


def test_real_head_replay_owned_loopback_and_no_credential_forwarding(tmp_path, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), HeadOnlyHandler)
    HeadOnlyHandler.received = []
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
        profile = tmp_path / "scope.json"
        profile.write_text(json.dumps({
            "program": "Owned HEAD fixture", "platform": "local-lab",
            "authorization_reference": "Owned disposable HEAD service",
            "acknowledged_authorization": True,
            "allowed_hosts": ["127.0.0.1"], "allowed_ports": [port],
            "allowed_paths": ["/"], "methods": ["HEAD"],
            "lab_mode": True, "allow_http": True, "allow_private_network": True,
            "max_requests": 1, "interval_seconds": 1,
        }))
        imported = tmp_path / "imported.json"
        imported.write_text(json.dumps({
            "engine": "hunterqa_authorized_bounty_observation",
            "mode": "offline_har_import", "program": "Owned HEAD fixture",
            "platform": "local-lab",
            "policy_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
            "observations": [{
                "url": f"http://127.0.0.1:{port}/public",
                "method": "HAR", "status": 200,
            }],
        }))
        report = replay_har_head(profile, imported, authorized=True)
        assert report["summary"]["requests_attempted"] == 1
        assert report["summary"]["status_differences"] == 0
        assert report["comparisons"][0]["observed_header_names"] == ["content-type"]
        assert len(HeadOnlyHandler.received) == 1
        assert HeadOnlyHandler.received[0]["method"] == "HEAD"
        assert HeadOnlyHandler.received[0]["path"] == "/public"
        assert HeadOnlyHandler.received[0]["authorization"] is None
        assert HeadOnlyHandler.received[0]["cookie"] is None
        assert "never-exported" not in json.dumps(report)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
