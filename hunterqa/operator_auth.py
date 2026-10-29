"""Opt-in authenticated local dashboard roles; loopback restrictions stay active."""
from __future__ import annotations

import sqlite3
from datetime import timedelta

from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request, session, url_for

from . import operator_store as store
from .security import valid_csrf
from .db import get_db

bp = Blueprint("operators", __name__)
WRITE_ENDPOINTS = {"main.create_project", "main.start_scan", "main.update_triage_review"}


def _database():
    return current_app.config["OPERATOR_DATABASE"]


def _csrf():
    if not valid_csrf(request.form.get("csrf_token")):
        abort(400, "Invalid form token. Refresh the page and try again.")


def _unavailable():
    abort(503, "Operator access is unavailable. Contact the local OS administrator.")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if g.operator:
            return redirect(url_for("main.dashboard"))
        return render_template("operator_login.html", error=None)
    _csrf()
    try:
        user, status, instance, token = store.authenticate(_database(), request.form.get("username", ""),
            request.form.get("password", ""), request.remote_addr or "")
    except (OSError, ValueError, TypeError, sqlite3.Error):
        return _unavailable()
    if status == "throttled":
        return render_template("operator_login.html", error="Sign-in limit reached. Try again after the local rate window expires."), 429, {"Retry-After": "600"}
    if status != "ok":
        return render_template("operator_login.html", error="Sign-in failed. Check your credentials or contact the local administrator."), 401
    session.clear()
    session.permanent = True
    session["operator_session"] = token
    session["operator_instance"] = instance
    return redirect(url_for("main.dashboard"))


@bp.post("/logout")
def logout():
    _csrf()
    try:
        store.revoke_session(_database(), session.get("operator_session"))
    except (OSError, ValueError, TypeError, sqlite3.Error):
        return _unavailable()
    session.clear()
    return redirect(url_for("operators.login"))


@bp.get("/operators")
def operators():
    if g.operator["role"] != "admin":
        abort(403, "Administrator access is required.")
    try:
        return render_template("operator_users.html", identities=store.status(_database()), audit=store.audit_status(_database()))
    except (OSError, ValueError, TypeError, sqlite3.Error):
        return _unavailable()


def init_operator_auth(app, *, persistent_secret):
    with app.app_context():
        required = get_db().execute("SELECT operator_required FROM dashboard_security WHERE id=1").fetchone()[0]
    if not app.config.get("OPERATOR_DATABASE"):
        if required:
            raise ValueError("This dashboard previously enabled operator authentication; restore its operator configuration")
        @app.context_processor
        def no_operator_auth():
            return {"operator_read_only": False}
        return
    if not persistent_secret or not isinstance(app.config["SECRET_KEY"], str) or len(app.config["SECRET_KEY"]) < 32:
        raise ValueError("Operator mode requires an explicitly configured persistent 32+ character session secret")
    if app.config.get("SESSION_COOKIE_DOMAIN") is not None:
        raise ValueError("Operator cookies must remain host-only")
    store.validate_separation(app.config.get("APPROVED_ROOTS", ""))
    store.status(app.config["OPERATOR_DATABASE"])  # Missing/invalid identity configuration fails closed at startup.
    store.dummy_hash()
    with app.app_context():
        with get_db() as db:
            db.execute("UPDATE dashboard_security SET operator_required=1 WHERE id=1")
    app.config.update(SESSION_COOKIE_NAME="hunterqa_operator", SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict", SESSION_REFRESH_EACH_REQUEST=False,
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=store.SESSION_SECONDS))
    app.register_blueprint(bp)

    @app.before_request
    def enforce_operator_access():
        g.operator = None
        try:
            token, instance = session.get("operator_session"), session.get("operator_instance")
            if token or instance:
                g.operator = store.session_operator(_database(), token, instance)
                if g.operator is None:
                    session.clear()
        except (OSError, ValueError, TypeError, sqlite3.Error):
            return _unavailable()
        if request.endpoint in ("static", "operators.login"):
            return None
        if g.operator is None:
            if request.path.startswith("/api/") or request.method not in ("GET", "HEAD"):
                return jsonify({"error": "Operator sign-in required"}), 401
            return redirect(url_for("operators.login"))
        if request.endpoint == "operators.logout":
            return None
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            allowed = g.operator["role"] in ("analyst", "admin") and request.endpoint in WRITE_ENDPOINTS
            try:
                store.audit_event(_database(), "mutation-permitted" if allowed else "mutation-denied",
                    g.operator["username"] + ":" + (request.endpoint or "unknown"))
            except (OSError, ValueError, TypeError, sqlite3.Error):
                return _unavailable()
            if not allowed:
                abort(403, "Your operator role cannot make this change.")
        return None

    @app.context_processor
    def operator_context():
        user = getattr(g, "operator", None)
        return {"operator_read_only": bool(user and user["role"] == "viewer")}
