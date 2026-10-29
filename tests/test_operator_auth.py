import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from hunterqa import create_app, operator_store
from hunterqa.cli import main
from hunterqa.security import AUTHORIZATION_TEXT

PASSWORD = "Owned-operator-fixture-password!"


@pytest.fixture
def operators(tmp_path, monkeypatch, fake_service):
    control, cases = tmp_path / "control", tmp_path / "cases"
    control.mkdir(mode=0o700)
    cases.mkdir()
    (cases / "source").mkdir()
    monkeypatch.setenv("HUNTERQA_OPERATOR_ROOT", str(control))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(cases))
    monkeypatch.delenv("HUNTERQA_OPERATOR_DB", raising=False)
    monkeypatch.delenv("HUNTERQA_OPERATOR_SESSION_KEY_FILE", raising=False)
    path = control / "operators.sqlite3"
    operator_store.initialize(path, "admin", PASSWORD, authorized=True)
    operator_store.add_operator(path, "viewer", "viewer", PASSWORD, authorized=True)
    operator_store.add_operator(path, "analyst", "analyst", PASSWORD, authorized=True)
    config = {"TESTING": True, "SECRET_KEY": "owned-session-key-" + "X" * 48,
        "DATABASE": str(tmp_path / "dashboard.sqlite3"), "APPROVED_ROOTS": [str(cases)],
        "OPERATOR_DATABASE": str(path), "SCAN_SERVICE": fake_service}
    app = create_app(config)
    return app, path, cases, config, fake_service


def csrf(client):
    with client.session_transaction() as session:
        return session["csrf_token"]


def sign_in(client, username="viewer", password=PASSWORD):
    client.get("/login")
    return client.post("/login", data={"username": username, "password": password, "csrf_token": csrf(client)})


def test_login_required_for_html_api_and_mutations_and_local_gate_stays_first(operators):
    app, _, cases, _, _ = operators
    client = app.test_client()
    response = client.get("/projects")
    assert response.status_code == 302 and response.location.endswith("/login")
    assert client.get("/api/scans/1/status").status_code == 401
    assert client.post("/projects", data={"name": "blocked", "path": str(cases)}).status_code == 401
    assert client.get("/login", environ_overrides={"REMOTE_ADDR": "203.0.113.10"}).status_code == 403
    assert client.get("/login", headers={"Host": "outside.example.test"}).status_code == 400
    assert client.get("/static/app.css").status_code == 200
    assert client.post("/login", data={"username": "admin", "password": PASSWORD}).status_code == 400


def test_viewer_cannot_write_even_with_a_valid_csrf_token_or_client_role_claim(operators):
    app, _, cases, _, service = operators
    client = app.test_client()
    assert sign_in(client).status_code == 302
    response = client.get("/projects")
    assert response.status_code == 200 and b"View-only access" in response.data
    assert b'id="project-modal"' not in response.data
    with client.session_transaction() as session:
        session["role"] = "admin"  # Client-side role fields are never trusted.
    assert client.post("/projects", data={"name": "blocked", "path": str(cases / "source"), "csrf_token": csrf(client)}).status_code == 403
    assert client.post("/projects/1/scans", data={"csrf_token": csrf(client)}).status_code == 403
    assert client.post("/triage/review/example", data={"csrf_token": csrf(client)}).status_code == 403
    assert client.get("/operators").status_code == 403
    assert not service.submitted


def test_analyst_can_use_existing_gates_but_has_no_operator_administration(operators):
    app, _, cases, _, service = operators
    client = app.test_client()
    assert sign_in(client, "analyst").status_code == 302
    client.get("/projects")
    assert client.post("/projects", data={"name": "Owned source", "path": str(cases / "source"), "csrf_token": csrf(client)}).status_code == 302
    assert client.post("/projects/1/scans", data={"csrf_token": csrf(client)}).status_code == 302
    assert not service.submitted  # The original typed assessment attestation is still required.
    response = client.post("/projects/1/scans", data={"csrf_token": csrf(client), "authorized": "yes", "authorization_text": AUTHORIZATION_TEXT})
    assert response.status_code == 302 and service.submitted == [1]
    assert client.get("/operators").status_code == 403


def test_admin_can_view_operator_state_but_new_mutation_routes_fail_closed(operators):
    app, path, _, _, _ = operators
    executed = []
    app.add_url_rule("/future-write", endpoint="future.write", methods=["POST"], view_func=lambda: executed.append(True) or "ok")
    client = app.test_client()
    assert sign_in(client, "admin").status_code == 302
    response = client.get("/operators")
    assert response.status_code == 200 and b"Authentication audit" in response.data
    assert PASSWORD.encode() not in response.data and b"pbkdf2:" not in response.data
    assert client.post("/future-write", data={"csrf_token": csrf(client)}).status_code == 403
    assert not executed
    assert operator_store.audit_status(path)["events"] >= 5


def test_logout_revokes_copied_cookie_and_rotates_csrf(operators):
    app, _, _, _, _ = operators
    client = app.test_client()
    client.get("/login")
    old_csrf = csrf(client)
    assert sign_in(client).status_code == 302
    client.get("/projects")
    assert csrf(client) != old_csrf
    cookie = client.get_cookie("hunterqa_operator").value
    assert client.get("/logout").status_code == 405
    assert client.post("/logout", data={"csrf_token": "wrong"}).status_code == 400
    assert client.post("/logout", data={"csrf_token": csrf(client)}).status_code == 302
    client.set_cookie("hunterqa_operator", cookie)
    assert client.get("/projects").status_code == 302
    assert client.get("/api/scans/1/status").status_code == 401


@pytest.mark.parametrize("change", ["disable", "password", "role"])
def test_operator_changes_revoke_existing_sessions_immediately(operators, change):
    app, path, _, _, _ = operators
    client = app.test_client()
    assert sign_in(client).status_code == 302
    kwargs = {"active": False} if change == "disable" else {"password": "New-owned-fixture-password!"} if change == "password" else {"role": "analyst"}
    operator_store.update_operator(path, "viewer", authorized=True, **kwargs)
    assert client.get("/projects").status_code == 302


def test_session_expiration_and_database_failure_do_not_fall_back_to_open_access(operators):
    app, path, _, _, _ = operators
    client = app.test_client()
    assert sign_in(client).status_code == 302
    with operator_store.database(path, write=True) as db:
        db.execute("UPDATE operator_sessions SET expires=0")
    assert client.get("/projects").status_code == 302
    assert sign_in(client).status_code == 302
    path.rename(path.with_suffix(".saved"))
    assert client.get("/projects").status_code == 503


def test_rate_limits_persist_across_app_restarts_and_wrong_names_are_generic(operators):
    app, _, _, config, _ = operators
    client = app.test_client()
    failed = sign_in(client, "viewer", "wrong-owned-fixture")
    assert failed.status_code == 401 and PASSWORD.encode() not in failed.data
    unknown = sign_in(client, "unknown", "wrong-owned-fixture")
    assert unknown.status_code == 401 and b"Sign-in failed" in failed.data and b"Sign-in failed" in unknown.data
    for _ in range(9):
        assert sign_in(client, "viewer", "wrong-owned-fixture").status_code == 401
    assert sign_in(client, "viewer", PASSWORD).status_code == 429
    other = create_app(config).test_client()
    assert sign_in(other, "viewer", PASSWORD).status_code == 429


def test_control_roots_separation_last_admin_and_password_storage(operators):
    _, path, cases, config, _ = operators
    with operator_store.database(path) as db:
        hashes = [row[0] for row in db.execute("SELECT password_hash FROM operators")]
    assert all(h.startswith("pbkdf2:sha256:1000000$") for h in hashes)
    assert len(set(hashes)) == 3 and PASSWORD not in path.read_bytes().decode(errors="ignore")
    with pytest.raises(ValueError, match="last active"):
        operator_store.update_operator(path, "admin", active=False, authorized=True)
    with pytest.raises(ValueError, match="overlap"):
        create_app({**config, "APPROVED_ROOTS": [str(cases.parent)]})
    with pytest.raises(ValueError, match="session secret"):
        create_app({**config, "SECRET_KEY": "too-short"})
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_last_admin_rule_is_atomic_across_concurrent_updates(operators):
    _, path, _, _, _ = operators
    operator_store.add_operator(path, "other-admin", "admin", PASSWORD, authorized=True)

    def disable(name):
        try:
            operator_store.update_operator(path, name, active=False, authorized=True)
            return "disabled"
        except ValueError:
            return "protected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(disable, ["admin", "other-admin"]))
    assert sorted(results) == ["disabled", "protected"]
    assert sum(u["role"] == "admin" and u["active"] for u in operator_store.status(path)["operators"]) == 1


def test_private_control_path_and_missing_session_secret_fail_closed(operators, monkeypatch):
    _, path, _, config, _ = operators
    with pytest.raises(ValueError, match="control root"):
        operator_store.status(path.parent.parent / "outside.sqlite3")
    monkeypatch.delenv("HUNTERQA_SECRET_KEY", raising=False)
    monkeypatch.delenv("ZEROSCOPE_SECRET_KEY", raising=False)
    changed = dict(config)
    del changed["SECRET_KEY"]
    with pytest.raises(ValueError, match="session secret"):
        create_app(changed)


def test_operator_mode_cannot_silently_revert_to_anonymous_on_restart(operators):
    _, _, _, config, _ = operators
    with pytest.raises(ValueError, match="previously enabled"):
        create_app({**config, "OPERATOR_DATABASE": ""})


def test_private_session_key_file_setup_and_readiness(operators, monkeypatch, capsys):
    from hunterqa.assessment_readiness import assessment_readiness
    _, path, _, config, _ = operators
    key_file = path.parent / "session-key"
    main(["operator-secret", "--out", str(key_file), "--authorized"])
    result = json.loads(capsys.readouterr().out)
    key = operator_store.read_session_key(key_file)
    assert result["created"] and not result["secret_value_displayed"] and key not in json.dumps(result)
    with pytest.raises(FileExistsError):
        operator_store.create_session_key(key_file, authorized=True)
    monkeypatch.delenv("HUNTERQA_SECRET_KEY", raising=False)
    monkeypatch.delenv("ZEROSCOPE_SECRET_KEY", raising=False)
    monkeypatch.setenv("HUNTERQA_OPERATOR_SESSION_KEY_FILE", str(key_file))
    monkeypatch.setenv("HUNTERQA_OPERATOR_DB", str(path))
    changed = dict(config)
    del changed["SECRET_KEY"]
    app = create_app(changed)
    assert app.secret_key == key
    readiness = assessment_readiness()
    assert next(c for c in readiness["checks"] if c["name"] == "operator_access")["status"] == "ok"
    assert key not in json.dumps(readiness)
    monkeypatch.setenv("HUNTERQA_SECRET_KEY", "X" * 64)
    with pytest.raises(ValueError, match="not both"):
        create_app(changed)


def test_operator_audit_tampering_is_detected(operators):
    _, path, _, _, _ = operators
    with operator_store.database(path, write=True) as db:
        db.execute("UPDATE operator_audit SET sha256='tampered' WHERE seq=1")
    with pytest.raises(ValueError, match="inconsistent"):
        operator_store.audit_status(path)


def test_control_secrets_cannot_be_created_inside_a_git_checkout(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").mkdir()
    control = checkout / "private-control"
    control.mkdir(mode=0o700)
    monkeypatch.setenv("HUNTERQA_OPERATOR_ROOT", str(control))
    with pytest.raises(ValueError, match="outside Git"):
        operator_store.create_session_key(control / "session-key", authorized=True)
    assert not list(control.iterdir())


def test_cli_management_never_prints_passwords_or_hashes(operators, monkeypatch, capsys):
    _, path, _, _, _ = operators
    monkeypatch.setenv("HUNTERQA_OPERATOR_PASSWORD", "Different-owned-fixture-password!")
    main(["operator-add", "--database", str(path), "--username", "reviewer", "--role", "viewer", "--authorized"])
    text = capsys.readouterr().out
    assert "Different-owned-fixture-password!" not in text and "password_hash" not in text
    assert any(u["username"] == "reviewer" for u in json.loads(text)["operators"])
    main(["operator-audit", "--database", str(path)])
    assert json.loads(capsys.readouterr().out)["events"] >= 4
    with pytest.raises(PermissionError):
        main(["operator-add", "--database", str(path), "--username", "blocked", "--role", "admin"])


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Opt-in owned operator browser test")
def test_operator_sign_in_read_only_view_and_sign_out_real_browser(operators):
    from playwright.sync_api import sync_playwright, expect
    from werkzeug.serving import make_server
    app, _, _, _, _ = operators
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as driver:
            browser = driver.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": 390, "height": 844})
                page.goto(f"http://127.0.0.1:{server.server_port}/projects")
                expect(page.get_by_role("heading", name="Sign in to HunterQA")).to_be_visible()
                page.get_by_label("Username", exact=True).fill("viewer")
                page.get_by_label("Password", exact=True).fill(PASSWORD)
                page.get_by_role("button", name="Sign in", exact=True).click()
                page.goto(f"http://127.0.0.1:{server.server_port}/projects")
                expect(page.get_by_text("View-only access.", exact=False)).to_be_visible()
                expect(page.get_by_role("button", name="+ Add project", exact=True)).to_have_count(0)
                assert page.locator("body").evaluate("el => el.scrollWidth <= window.innerWidth")
                page.get_by_role("button", name="Sign out", exact=True).click()
                expect(page.get_by_role("heading", name="Sign in to HunterQA")).to_be_visible()
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
