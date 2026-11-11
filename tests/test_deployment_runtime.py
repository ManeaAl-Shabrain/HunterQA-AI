"""Deployment specification injection controls and actual loopback health probes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest
from flask import Flask, redirect
from werkzeug.serving import make_server

from hunterqa import create_app
from tests import test_workspaces as workspace_tests, test_workspace_edge as edge_tests
from tools.render_deployment import render, validate
from tools.verify_deployment import health

ROOT = Path(__file__).resolve().parents[1]


def specification():
    return json.loads((ROOT / "examples/deploy/deployment.example.json").read_text())


@pytest.mark.parametrize("key,value", [("home", "/srv/../etc"), ("home", "/srv/a\nEnvironment=EVIL=1"),
    ("home", "/srv/$HOME"), ("home", "/srv/%h"), ("home", "/srv/a b"), ("home", "/srv//a"),
    ("home", "/srv/a/"), ("home", "/srv"), ("runtime_prefix", "/srv/hunterqa-alpha/runtime"),
    ("uid", 0), ("uid", True), ("gid", -1), ("user", "root"), ("user", "a;evil"),
    ("workspace_id", "../evil"), ("workspace_id", "A"), ("port", 443), ("port", True),
    ("port", 65536), ("schema_version", True)])
def test_unsafe_or_privileged_deployment_specs_rejected(key, value):
    data = specification()
    data[key] = value
    with pytest.raises(ValueError):
        validate(data)


def test_non_secret_spec_refuses_unknown_fields():
    data = specification()
    data["password"] = "never place credentials in the deployment specification"
    with pytest.raises(ValueError):
        render(data)


def test_one_spec_renders_same_paths_and_rejects_overwrite(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(specification()))
    destination = tmp_path / "rendered"
    destination.mkdir(mode=0o700)
    command = [sys.executable, str(ROOT / "tools/render_deployment.py"), "--config", str(spec), "--out-dir", str(destination)]
    output = subprocess.run(command, capture_output=True, text=True, check=True, timeout=15)
    assert not json.loads(output.stdout)["secrets_included"]
    env = dict(line.split("=", 1) for line in (destination / "runtime.env").read_text().splitlines())
    unit = (destination / "hunterqa-alpha.service").read_text()
    assert "--config " + env["HUNTERQA_HOME"] + "/control/alpha/workspace.json" in unit
    assert "User=hunterqa-alpha" in unit and "NoNewPrivileges=yes" in unit
    assert os.name != "posix" or (destination / "runtime.env").stat().st_mode & 0o077 == 0
    prior = {p.name: p.read_bytes() for p in destination.iterdir()}
    rejected = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert rejected.returncode != 0
    assert prior == {p.name: p.read_bytes() for p in destination.iterdir()}


@pytest.fixture
def spaces(tmp_path, monkeypatch):
    return workspace_tests.spaces.__wrapped__(tmp_path, monkeypatch)


@pytest.mark.parametrize("public", [False, True])
def test_actual_health_probe_supports_local_and_keyed_profiles_without_idp_contact(spaces, monkeypatch, public):
    config = spaces[2][0]
    if public:
        config, _ = edge_tests.configured(spaces)
    app = create_app({"WORKSPACE_CONFIG": str(config), "TESTING": True, "SCAN_SERVICE": workspace_tests.Service()})
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("HUNTERQA_WORKSPACE_CONFIG", str(config))
    monkeypatch.setenv("HUNTERQA_PORT", str(server.server_port))
    try:
        result = health()
        assert result["healthy"] and not result["provider_login_verified"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_private_health_headers_never_follow_a_redirect(spaces, monkeypatch):
    config, key = edge_tests.configured(spaces)
    app = Flask("owned-redirect")
    app.add_url_rule("/login", view_func=lambda: redirect("http://127.0.0.1:9/never-contact"))
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("HUNTERQA_WORKSPACE_CONFIG", str(config))
    monkeypatch.setenv("HUNTERQA_PORT", str(server.server_port))
    try:
        assert not health()["healthy"]
        assert key not in json.dumps(health())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
