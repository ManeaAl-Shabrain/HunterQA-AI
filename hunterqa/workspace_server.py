"""Bounded loopback WSGI serving with a single-host workspace lease."""
from contextlib import closing, contextmanager
import os
from pathlib import Path

from . import workspace
from .engagement import utcnow


@contextmanager
def lease(root):
    path = Path(root) / "state" / "server.lock"
    if path.is_symlink():
        raise ValueError("Symlinked workspace lease rejected")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    locked = False
    try:
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"0")
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError:
            raise RuntimeError("This workspace is already served by another process") from None
        yield
    finally:
        if locked:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def recover_interrupted(app):
    from .db import connect
    with closing(connect(app.config["DATABASE"])) as db, db:
        cursor = db.execute("UPDATE scans SET status='failed',progress=100,stage='Interrupted by restart',error='Review evidence and explicitly authorize a new scan',finished_at=? WHERE status IN ('queued','running')", (utcnow().isoformat(),))
        return cursor.rowcount


def recover(config, *, authorized=False):
    if authorized is not True:
        raise PermissionError("Offline workspace recovery requires --authorized")
    settings = workspace.load(config)
    with lease(settings["WORKSPACE_ROOT"]):
        from . import create_app
        from .operator_store import audit_event
        app = create_app({"WORKSPACE_CONFIG": str(config)})
        audit_event(settings["OPERATOR_DATABASE"], "os-admin-recover-interrupted-scans", settings["WORKSPACE_ID"])
        count = recover_interrupted(app)
    return {"engine": "workspace-offline-recovery", "workspace_id": settings["WORKSPACE_ID"],
        "scans_marked_failed": count, "scans_replayed": 0, "network_requests": 0, "production_ready": False}


def server_options(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Choose an explicit local WSGI port from 1..65535")
    return {"host": "127.0.0.1", "port": port, "threads": 4, "connection_limit": 64, "backlog": 64,
        "channel_timeout": 30, "cleanup_interval": 5, "max_request_header_size": 8192,
        "max_request_body_size": 1048576, "expose_tracebacks": False,
        # Preserve raw headers for the authenticated edge middleware; do not
        # let the WSGI server rewrite peer identity before that check.
        "trusted_proxy": None, "clear_untrusted_proxy_headers": False}


def serve(config, port, *, require_auth_policy=False):
    from importlib.metadata import version
    from packaging.version import Version
    try:
        from waitress import serve as waitress_serve
        if Version(version("waitress")) < Version("3.0.2"):
            raise ImportError
    except ImportError:
        raise RuntimeError("Install .[production] before workspace serving") from None
    settings = workspace.load(config)
    if require_auth_policy and not settings.get("AUTH_CONFIG"):
        raise ValueError("Configure unified authentication and enroll administrator MFA before serving this profile")
    options = server_options(port)
    with lease(settings["WORKSPACE_ROOT"]):
        from . import create_app
        app = create_app({"WORKSPACE_CONFIG": config})
        recover_interrupted(app)
        waitress_serve(app, **options)


def readiness(config):
    from . import create_app
    app = create_app({"WORKSPACE_CONFIG": config})
    return {"engine": "workspace-startup-readiness", "schema_version": 1, "workspace_id": app.config["WORKSPACE_ID"],
        "startup_configuration_valid": True, "separate_data_and_identity_stores": True,
        "sso_configured": bool(app.config.get("OIDC_ENABLED") or app.config.get("AUTH_PROVIDERS")),
        "unified_authentication_configured": bool(app.config.get("AUTH_POLICY_ENABLED")),
        "administrator_mfa_required": bool(app.config.get("AUTH_POLICY_ENABLED")),
        "local_configuration_ready": bool(app.config.get("AUTH_POLICY_ENABLED") and app.config.get("AUTH_LOCAL_ENABLED")
            and not app.config.get("WORKSPACE_PUBLIC_ORIGIN")),
        "normal_local_operation_requires_public_https": False,
        "optional_sso_providers_enabled": app.config.get("AUTH_PROVIDERS", []),
        "authenticated_https_edge_configured": bool(app.config.get("WORKSPACE_PUBLIC_ORIGIN")),
        "network_requests": 0, "production_ready": False,
        "unverified": ["Real provider registration, MFA/session policy and end-to-end login in the intended deployment",
            "OS account/container isolation, denied-egress validation and real TLS edge deployment",
            "Independent owner grants, cross-host quotas and distributed workers",
            "Representative independent assessment accuracy, load/failure tests and backup/restore operations"],
        "scope": "Configuration/startup validation only; owned regression controls are not independent production certification"}
