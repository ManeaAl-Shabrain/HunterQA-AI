"""HunterQA dashboard; local by default, explicit isolated-workspace profiles."""
from __future__ import annotations
import os
import secrets
import shutil
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit
from flask import Flask, abort, g, request
from .db import init_app as init_db
from .routes import bp
from .scanner import ScanService
from .formatting import safe_report_markdown


def _env(name: str, legacy: str, default: str = "") -> str:
    return os.environ.get(name) or os.environ.get(legacy) or default


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    pkg = Path(__file__).resolve().parent
    from .workspace import load as load_workspace, bind_database
    workspace = load_workspace((test_config or {}).get("WORKSPACE_CONFIG") or os.environ.get("HUNTERQA_WORKSPACE_CONFIG"))
    if workspace:
        app.instance_path = str(Path(workspace["WORKSPACE_ROOT"]) / "state")
    persistent_key = workspace["SECRET_KEY"] if workspace else _env("HUNTERQA_SECRET_KEY", "ZEROSCOPE_SECRET_KEY")
    operator_key_file = None if workspace else os.environ.get("HUNTERQA_OPERATOR_SESSION_KEY_FILE")
    if operator_key_file:
        if persistent_key:
            raise ValueError("Configure a session-key file or an environment session secret, not both")
        from .operator_store import read_session_key
        persistent_key = read_session_key(operator_key_file)
    app.config.from_mapping(
        SECRET_KEY=persistent_key or secrets.token_hex(32),
        DATABASE=str(Path(app.instance_path) / "hunterqa.sqlite3"),
        APPROVED_ROOTS=_env("HUNTERQA_APPROVED_ROOTS", "ZEROSCOPE_APPROVED_ROOTS"),
        SEMGREP_RULES=str(pkg / "rules" / "semgrep.yml"),
        OLLAMA_URL="http://127.0.0.1:11434",
        OLLAMA_MODEL=_env("HUNTERQA_OLLAMA_MODEL", "ZEROSCOPE_OLLAMA_MODEL", "qwen2.5-coder:3b"),
        SCAN_TIMEOUT_SECONDS=int(_env("HUNTERQA_SCAN_TIMEOUT", "ZEROSCOPE_SCAN_TIMEOUT", "900")),
        RESEARCH_REPORT_PATH=os.environ.get("HUNTERQA_RESEARCH_REPORT", ""),
        TRIAGE_REPORT_PATH=os.environ.get("HUNTERQA_TRIAGE_REPORT", ""),
        CVE_REPORT_PATH=os.environ.get("HUNTERQA_CVE_REPORT", ""),
        BOUNTY_REPORT_PATH=os.environ.get("HUNTERQA_BOUNTY_REPORT", ""),
        AGENT_PLAN_PATH=os.environ.get("HUNTERQA_AGENT_PLAN", ""),
        API_SURFACE_REPORT_PATH=os.environ.get("HUNTERQA_API_SURFACE_REPORT", ""),
        AGENT_CORRELATION_REPORT_PATH=os.environ.get("HUNTERQA_AGENT_CORRELATION_REPORT", ""),
        BROWSER_LAB_REPORT_PATH=os.environ.get("HUNTERQA_BROWSER_LAB_REPORT", ""),
        HEAD_REPLAY_REPORT_PATH=os.environ.get("HUNTERQA_HEAD_REPLAY_REPORT", ""),
        REVIEW_DOSSIER_PATH=os.environ.get("HUNTERQA_REVIEW_DOSSIER", ""),
        BENCHMARK_REPORT_PATH=os.environ.get("HUNTERQA_BENCHMARK_REPORT", ""),
        ENGAGEMENT_REPORT_PATH=os.environ.get("HUNTERQA_ENGAGEMENT_REPORT", ""),
        ENGAGEMENT_BASELINE_PATH=os.environ.get("HUNTERQA_ENGAGEMENT_BASELINE", ""),
        WORKFLOW_RUN_PATH=os.environ.get("HUNTERQA_WORKFLOW_RUN", ""),
        OPERATOR_DATABASE=os.environ.get("HUNTERQA_OPERATOR_DB", ""),
        OIDC_CONFIG=os.environ.get("HUNTERQA_OIDC_CONFIG", ""),
        AUTH_CONFIG=os.environ.get("HUNTERQA_AUTH_CONFIG", ""),
        CAMPAIGN_HISTORY_ROOT=os.environ.get("HUNTERQA_CAMPAIGN_HISTORY_ROOT", ""),
        HYPOTHESES_REPORT_PATH=os.environ.get("HUNTERQA_HYPOTHESES_REPORT", ""),
        FUZZ_STATS_PATH=os.environ.get("HUNTERQA_FUZZ_STATS", ""),
        MAX_CONTENT_LENGTH=1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    if workspace:
        if test_config and any(key in workspace and value != workspace[key] for key, value in test_config.items()):
            raise ValueError("Workspace data, identity and secret bindings cannot be overridden")
        app.config.update(workspace)
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    # Preserve existing SQLite history during the package name/branding migration.
    if not workspace and (not test_config or "DATABASE" not in test_config):
        old = Path(app.instance_path) / "zeroscope.sqlite3"
        new = Path(app.config["DATABASE"])
        if old.is_file() and not new.exists():
            shutil.copy2(old, new)
    init_db(app)
    bind_database(app)
    app.register_blueprint(bp)
    app.jinja_env.globals["safe_report_markdown"] = safe_report_markdown
    app.extensions["scan_service"] = app.config.get("SCAN_SERVICE") or ScanService(app)
    @app.before_request
    def enforce_local_dashboard():
        # Direct mode ignores forwarded identity. Workspace edge admission runs
        # before Flask and supplies a private verified marker, not a client header.
        try:
            peer = ipaddress.ip_address(request.remote_addr or "")
            authority = urlsplit("//" + request.host)
            valid_host = (authority.hostname in {"localhost", "127.0.0.1", "::1"}
                          and authority.username is None and authority.password is None
                          and not authority.path and not authority.query and not authority.fragment)
            port = authority.port
            valid_host = valid_host and (port is None or 1 <= port <= 65535)
        except ValueError:
            abort(400)
        edge = app.config.get("WORKSPACE_PUBLIC_ORIGIN")
        if edge:
            if request.environ.get("hunterqa.edge_verified") is not True:
                abort(403)
            valid_host = request.host == urlsplit(edge).netloc
        elif not peer.is_loopback:
            abort(403)
        if not valid_host:
            abort(400)
        g.csp_nonce = secrets.token_urlsafe(18)

    from .operator_auth import init_operator_auth
    init_operator_auth(app, persistent_secret=bool(persistent_key
        or (test_config and test_config.get("SECRET_KEY"))))
    from .identity_routes import init_identity
    init_identity(app)
    if not app.config.get("AUTH_POLICY_ENABLED"):
        from .operator_oidc import init_oidc
        init_oidc(app)

    @app.context_processor
    def browser_policy_context():
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    @app.after_request
    def secure_headers(response):
        if app.config.get("WORKSPACE_PUBLIC_ORIGIN"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        nonce = getattr(g, "csp_nonce", "")
        response.headers.setdefault("Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "form-action 'self'" + (" " + app.config["OIDC_FORM_ACTION"] if app.config.get("OIDC_FORM_ACTION") else "") + "; frame-ancestors 'none'")
        return response
    if app.config.get("WORKSPACE_PUBLIC_ORIGIN"):
        from .trusted_edge import TrustedEdge
        app.wsgi_app = TrustedEdge(app.wsgi_app, app.config["WORKSPACE_PUBLIC_ORIGIN"], app.config["WORKSPACE_EDGE_KEY"])
    return app
