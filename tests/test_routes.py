from __future__ import annotations

import json

from hunterqa.db import connect
from hunterqa.security import AUTHORIZATION_TEXT

from .conftest import csrf


def add_project(client, approved_root):
    return client.post("/projects", data={
        "csrf_token": csrf(client),
        "name": "Demo API",
        "path": str(approved_root / "demo"),
    })


def test_dashboard_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Source intelligence" in response.data


def test_project_must_be_inside_approved_root(client, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    response = client.post("/projects", data={
        "csrf_token": csrf(client), "name": "Outside", "path": str(outside)
    }, follow_redirects=True)
    assert b"outside the approved project roots" in response.data


def test_scan_requires_exact_authorization(client, approved_root, fake_service):
    add_project(client, approved_root)
    response = client.post("/projects/1/scans", data={
        "csrf_token": csrf(client), "authorized": "yes", "authorization_text": "almost"
    }, follow_redirects=True)
    assert b"Scan not started" in response.data
    assert fake_service.submitted == []


def test_authorized_scan_is_queued(client, approved_root, fake_service):
    add_project(client, approved_root)
    response = client.post("/projects/1/scans", data={
        "csrf_token": csrf(client), "authorized": "yes", "authorization_text": AUTHORIZATION_TEXT
    })
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/scans/1")
    assert fake_service.submitted == [1]


def test_json_export_contains_findings(app, client, approved_root):
    add_project(client, approved_root)
    with connect(app.config["DATABASE"]) as db:
        db.execute("INSERT INTO scans (project_id, status, progress, stage) VALUES (1, 'completed', 100, 'Completed')")
        db.execute("""INSERT INTO findings
          (scan_id, rule_id, title, severity, cwe, file_path, line_start, line_end, message, code)
          VALUES (1, 'rule', 'Unsafe call', 'ERROR', 'CWE-95', 'app.py', 4, 4, 'message', 'eval(x)')""")
    response = client.get("/scans/1/export.json")
    payload = json.loads(response.data)
    assert response.status_code == 200
    assert payload["schema_version"] == 2
    assert payload["findings"][0]["cwe"] == "CWE-95"
    assert response.headers["Content-Disposition"].endswith('hunterqa-scan-1.json"')


def test_csrf_is_required(client, approved_root):
    response = client.post("/projects", data={"name": "Demo", "path": str(approved_root / "demo")})
    assert response.status_code == 400

