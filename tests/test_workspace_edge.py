"""Authenticated proxy, real Waitress, host-local lease and capacity boundaries."""
import json
import multiprocessing
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from hunterqa import create_app
from hunterqa import workspace_server as serving
from hunterqa.db import connect
from hunterqa.scanner import ScanCapacityError, ScanService
from hunterqa.trusted_edge import public_origin
from tests import test_workspaces as workspace_tests

Service = workspace_tests.Service


@pytest.fixture
def spaces(tmp_path, monkeypatch):
    return workspace_tests.spaces.__wrapped__(tmp_path, monkeypatch)


def configured(spaces):
    control, roots, configs = spaces
    private = control / "alpha"
    secret = private / "client.secret"
    secret.write_text("owned-client-secret-for-HTTPS-12345\n")
    if os.name == "posix":
        secret.chmod(0o600)
    oidc = private / "oidc.json"
    oidc.write_text(json.dumps({"schema_version": 1, "issuer": "https://idp.fixture.test/tenant", "client_id": "owned-client",
        "authorization_endpoint": "https://idp.fixture.test/authorize", "token_endpoint": "https://idp.fixture.test/token",
        "jwks_uri": "https://idp.fixture.test/keys", "redirect_uri": "https://alpha.example.test/oidc/callback",
        "client_secret_file": str(secret), "bindings": [{"subject": "admin-subject", "username": "admin"}],
        "local_password_login": False, "allow_private_provider": False}))
    if os.name == "posix":
        oidc.chmod(0o600)
    data = json.loads(configs[0].read_text())
    data.update(oidc_config=str(oidc), public_origin="https://alpha.example.test", edge_key_file=str(private / "edge.key"))
    configs[0].write_text(json.dumps(data))
    key = (private / "edge.key").read_text().strip()
    return configs[0], key


def headers(key):
    return {"X-HunterQA-Edge-Key": key, "X-Forwarded-Proto": "https", "X-Forwarded-For": "198.51.100.40"}


@pytest.mark.parametrize("change,peer", [({"X-HunterQA-Edge-Key": "wrong"}, "127.0.0.1"),
    ({"X-Forwarded-Proto": "http"}, "127.0.0.1"), ({"X-Forwarded-For": "1.1.1.1, 2.2.2.2"}, "127.0.0.1"),
    ({"X-Forwarded-For": "0.0.0.0"}, "127.0.0.1"), ({}, "203.0.113.20"), ({"Host": "bravo.example.test"}, "127.0.0.1")])
def test_untrusted_peer_proxy_identity_or_host_denied_before_flask(spaces, change, peer):
    config, key = configured(spaces)
    app = create_app({"WORKSPACE_CONFIG": str(config), "TESTING": True, "SCAN_SERVICE": Service()})
    response = app.test_client().get("/login", base_url="https://alpha.example.test", headers={**headers(key), **change}, environ_overrides={"REMOTE_ADDR": peer})
    assert response.status_code == 403 and key.encode() not in response.data


def test_verified_edge_sets_secure_cookies_and_strips_untrusted_forwarding_headers(spaces):
    from flask import request
    config, key = configured(spaces)
    app = create_app({"WORKSPACE_CONFIG": str(config), "TESTING": True, "SCAN_SERVICE": Service()})
    seen = []
    @app.after_request
    def observe(response):
        seen.append((request.remote_addr, request.scheme, request.headers.get("Forwarded"), request.headers.get("X-HunterQA-Edge-Key")))
        return response
    response = app.test_client().get("/login", base_url="https://alpha.example.test", headers={**headers(key), "Forwarded": "for=evil;proto=http"})
    assert response.status_code == 200 and seen == [("198.51.100.40", "https", None, None)]
    assert "Secure" in response.headers["Set-Cookie"] and "HttpOnly" in response.headers["Set-Cookie"]
    assert "SameSite=Lax" in response.headers["Set-Cookie"] and "Domain=" not in response.headers["Set-Cookie"]
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert "https://idp.fixture.test/authorize" in response.headers["Content-Security-Policy"]
    assert key.encode() not in response.data and b"Continue with single sign-on" in response.data


@pytest.mark.parametrize("value", ["http://alpha.example.test", "https://u:p@alpha.example.test", "https://alpha.example.test/path",
    "https://alpha.example.test?x=1", "https://alpha.example.test:444", "https://*.example.test", "https://-bad.example"])
def test_edge_origin_is_canonical_and_exact(value):
    with pytest.raises(ValueError):
        public_origin(value)


def test_readiness_does_not_self_certify_a_configured_gateway(spaces):
    config, _ = configured(spaces)
    result = serving.readiness(str(config))
    assert result["startup_configuration_valid"] and result["sso_configured"]
    assert result["authenticated_https_edge_configured"] and not result["production_ready"]
    assert result["network_requests"] == 0 and result["unverified"]


def _hold_lease(root, ready, stop):
    with serving.lease(root):
        ready.put(True)
        stop.wait(20)


def test_os_file_lease_excludes_second_process_and_releases_on_exit(spaces):
    context = multiprocessing.get_context("spawn")
    ready, stop = context.Queue(), context.Event()
    process = context.Process(target=_hold_lease, args=(str(spaces[1][0]), ready, stop))
    process.start()
    try:
        assert ready.get(timeout=10)
        with pytest.raises(RuntimeError, match="already served"):
            with serving.lease(spaces[1][0]):
                pytest.fail("Second server acquired the workspace lease")
        stop.set()
        process.join(10)
        assert process.exitcode == 0
        with serving.lease(spaces[1][0]):
            pass
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)
        ready.close()


def test_worker_capacity_is_bounded_without_spawning_more_threads(spaces, monkeypatch):
    app = create_app({"WORKSPACE_CONFIG": str(spaces[2][0]), "TESTING": True, "SCAN_SERVICE": Service()})
    service = ScanService(app)
    service._active.update(range(1, 5))
    monkeypatch.setattr("hunterqa.scanner.threading.Thread", lambda *a, **k: pytest.fail("Full workspace spawned a worker"))
    with pytest.raises(ScanCapacityError):
        service.submit(5)
    assert service._active == {1, 2, 3, 4}


def test_concurrent_submissions_cannot_exceed_workspace_capacity(spaces, monkeypatch):
    from hunterqa import scanner
    app = create_app({"WORKSPACE_CONFIG": str(spaces[2][0]), "TESTING": True, "SCAN_SERVICE": Service()})
    service = ScanService(app)
    class Deferred:
        def __init__(self, *a, **k):
            pass
        def start(self):
            pass
    monkeypatch.setattr(scanner, "threading", SimpleNamespace(Thread=Deferred))
    def submit(scan):
        try:
            service.submit(scan)
            return True
        except ScanCapacityError:
            return False
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(submit, range(1, 11)))
    assert sum(results) == len(service._active) == 4


def test_web_capacity_failure_is_visible_and_does_not_leave_a_queued_record(spaces):
    from tests.test_workspaces import _login
    from hunterqa.security import AUTHORIZATION_TEXT
    class Full(Service):
        def submit(self, scan_id):
            raise ScanCapacityError("owned full queue")
    app = create_app({"WORKSPACE_CONFIG": str(spaces[2][0]), "TESTING": True, "SCAN_SERVICE": Full()})
    with connect(app.config["DATABASE"]) as db:
        db.execute("INSERT INTO projects(id,name,path) VALUES(1,'owned',?)", (app.config["APPROVED_ROOTS"][0],))
    client = app.test_client()
    assert _login(client).status_code == 302
    client.get("/projects")
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    response = client.post("/projects/1/scans", data={"csrf_token": csrf, "authorized": "yes", "authorization_text": AUTHORIZATION_TEXT})
    assert response.status_code == 429 and response.headers["Retry-After"] == "30"
    with connect(app.config["DATABASE"]) as db:
        assert db.execute("SELECT status FROM scans").fetchone()[0] == "failed"


def test_recovery_marks_interrupted_work_without_replaying_completed_scans(spaces):
    app = create_app({"WORKSPACE_CONFIG": str(spaces[2][0]), "TESTING": True, "SCAN_SERVICE": Service()})
    with connect(app.config["DATABASE"]) as db:
        db.execute("INSERT INTO projects(id,name,path) VALUES(1,'owned',?)", (app.config["APPROVED_ROOTS"][0],))
        for status in ("queued", "running", "completed"):
            db.execute("INSERT INTO scans(project_id,status) VALUES(1,?)", (status,))
    assert serving.recover_interrupted(app) == 2
    with connect(app.config["DATABASE"]) as db:
        assert [r[0] for r in db.execute("SELECT status FROM scans ORDER BY id")] == ["failed", "failed", "completed"]


def _real_server(config, ready):
    from waitress import create_server
    with serving.lease(json.loads(open(config, encoding="utf-8").read())["root"]):
        app = create_app({"WORKSPACE_CONFIG": config})
        options = serving.server_options(8080)
        options["port"] = 0  # Owned fixture only; CLI requires an explicit nonzero port.
        server = create_server(app, **options)
        ready.put(server.effective_port)
        server.run()


def test_real_waitress_keeps_raw_proxy_headers_for_authenticated_edge(spaces):
    pytest.importorskip("waitress")
    config, key = configured(spaces)
    context, ready = multiprocessing.get_context("spawn"), multiprocessing.get_context("spawn").Queue()
    process = context.Process(target=_real_server, args=(str(config), ready))
    process.start()
    try:
        port = ready.get(timeout=20)
        url = "http://127.0.0.1:" + str(port) + "/login"
        request = urllib.request.Request(url, headers={**headers(key), "Host": "alpha.example.test"})
        with urllib.request.urlopen(request, timeout=10) as response:
            assert response.status == 200 and b"Continue with single sign-on" in response.read()
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(url, timeout=10)
        assert rejected.value.code == 403
    finally:
        if process.is_alive():
            process.terminate()
        process.join(10)
        ready.close()
