"""HunterQA AI: local-only research dashboard and evidence processing."""
from __future__ import annotations
import os
import secrets
import shutil
from pathlib import Path
from flask import Flask
from .db import init_app as init_db
from .routes import bp
from .scanner import ScanService
from .formatting import safe_report_markdown


def _env(name: str, legacy: str, default: str = "") -> str:
    return os.environ.get(name) or os.environ.get(legacy) or default


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    pkg = Path(__file__).resolve().parent
    app.config.from_mapping(
        SECRET_KEY=_env("HUNTERQA_SECRET_KEY", "ZEROSCOPE_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=str(Path(app.instance_path) / "hunterqa.sqlite3"),
        APPROVED_ROOTS=_env("HUNTERQA_APPROVED_ROOTS", "ZEROSCOPE_APPROVED_ROOTS"),
        SEMGREP_RULES=str(pkg / "rules" / "semgrep.yml"),
        OLLAMA_URL="http://127.0.0.1:11434",
        OLLAMA_MODEL=_env("HUNTERQA_OLLAMA_MODEL", "ZEROSCOPE_OLLAMA_MODEL", "qwen2.5-coder:3b"),
        SCAN_TIMEOUT_SECONDS=int(_env("HUNTERQA_SCAN_TIMEOUT", "ZEROSCOPE_SCAN_TIMEOUT", "900")),
        RESEARCH_REPORT_PATH=os.environ.get("HUNTERQA_RESEARCH_REPORT", ""),
        HYPOTHESES_REPORT_PATH=os.environ.get("HUNTERQA_HYPOTHESES_REPORT", ""),
        FUZZ_STATS_PATH=os.environ.get("HUNTERQA_FUZZ_STATS", ""),
        MAX_CONTENT_LENGTH=1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    # Preserve existing SQLite history during the package name/branding migration.
    if not test_config or "DATABASE" not in test_config:
        old = Path(app.instance_path) / "zeroscope.sqlite3"
        new = Path(app.config["DATABASE"])
        if old.is_file() and not new.exists():
            shutil.copy2(old, new)
    init_db(app)
    app.register_blueprint(bp)
    app.jinja_env.globals["safe_report_markdown"] = safe_report_markdown
    app.extensions["scan_service"] = app.config.get("SCAN_SERVICE") or ScanService(app)
    @app.after_request
    def secure_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response
    return app
