"""Shared runtime health and opt-in owned deployment acceptance; never a real IdP test."""
import argparse
from contextlib import closing
import hashlib
from http.cookiejar import CookieJar
from importlib.metadata import distribution, version
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Public synthetic fixture credentials, never credentials for a real deployment.
PASSWORD = "Owned-deployment-fixture-2026!"  # nosec B105
RENEWED = "Renewed-owned-deployment-2026!"
FACTOR = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"  # public synthetic fixture only
RENEWED_FACTOR = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class LocalRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target, origin = urllib.parse.urlsplit(newurl), urllib.parse.urlsplit(req.full_url)
        if (target.scheme, target.netloc) != (origin.scheme, origin.netloc):
            raise ValueError("Owned deployment acceptance cannot leave its loopback origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def health(wait=0):
    from hunterqa.operator_store import _path, read_session_key
    from hunterqa.source_files import read_bounded
    from hunterqa.trusted_edge import public_origin
    port = int(os.environ["HUNTERQA_PORT"])
    if not 1024 <= port <= 65535:
        raise ValueError("Invalid configured loopback port")
    config = json.loads(read_bounded(_path(os.environ["HUNTERQA_WORKSPACE_CONFIG"]), 32768))
    headers = {}
    if config.get("public_origin"):
        headers = {"Host": urllib.parse.urlsplit(public_origin(config["public_origin"])).netloc,
            "X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1",
            "X-HunterQA-Edge-Key": read_session_key(config["edge_key_file"])}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    end = time.monotonic() + wait
    while True:
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/login", headers=headers)
            with opener.open(req, timeout=2) as response:
                if response.status == 200 and b"Sign in" in response.read(8192):
                    return {"healthy": True, "scope": "loopback login handler only", "provider_login_verified": False}
        except (OSError, urllib.error.URLError):
            pass
        if time.monotonic() >= end:
            return {"healthy": False, "scope": "loopback login handler only", "provider_login_verified": False}
        time.sleep(0.2)


def call(*args, password=None, input_text=None):
    env = dict(os.environ)
    if password is not None:
        env["HUNTERQA_OPERATOR_PASSWORD"] = password
    result = subprocess.run([sys.executable, "-m", "hunterqa", *map(str, args)], env=env,
        input=input_text, capture_output=True, text=True, timeout=90, check=True)  # nosec B603
    if any(secret in result.stdout for secret in (PASSWORD, RENEWED, FACTOR, RENEWED_FACTOR)):
        raise ValueError("Fixture credential appeared in command output")
    return json.loads(result.stdout)


def acceptance(phase):
    from hunterqa.workspace import _root
    if os.environ.get("HUNTERQA_OWNED_DEPLOYMENT_TEST") != "1":
        raise ValueError("Owned acceptance requires HUNTERQA_OWNED_DEPLOYMENT_TEST=1")
    home = _root(os.environ["HUNTERQA_HOME"])
    if os.name != "posix" or os.geteuid() == 0:
        raise ValueError("Owned runtime acceptance must run as an unprivileged Linux account")
    control, data = home / "control", home / "data"
    config = control / "owned-ci" / "workspace.json"
    if (os.environ.get("HUNTERQA_OPERATOR_ROOT") != str(control)
            or os.environ.get("HUNTERQA_WORKSPACE_CONFIG") != str(config)):
        raise ValueError("Acceptance only provisions the explicit owned-ci fixture")
    marker = home / "owned-acceptance.json"
    if phase == "init":
        if any(home.iterdir()):
            raise ValueError("Owned acceptance initialization requires an empty private home")
        for path in (control, data, home / "backups", home / "runtime-home"):
            path.mkdir(mode=0o700)
        call("workspace-init", "--workspace-id", "owned-ci", "--root", data, "--username", "admin", "--authorized", password=PASSWORD)
        call("operator-add", "--database", control / "owned-ci/operators.sqlite3", "--username", "viewer", "--role", "viewer", "--authorized", password=PASSWORD)
        call("operator-add", "--database", control / "owned-ci/operators.sqlite3", "--username", "analyst", "--role", "analyst", "--authorized", password=PASSWORD)
        call("identity-setup", "--config", config, "--origin", "http://127.0.0.1:" + os.environ["HUNTERQA_PORT"], "--authorized")
        call("operator-mfa-enroll", "--database", control / "owned-ci/operators.sqlite3", "--key-file", control / "owned-ci/auth.key", "--username", "admin", "--secret-stdin", "--authorized", input_text=FACTOR)
        project = data / "assessments/project"
        project.mkdir(mode=0o700)
        (project / "Dockerfile").write_text("FROM ubuntu:latest\nUSER root\n", encoding="utf-8")
        (project / "owned_parser_fixture.py").write_text("def example(value):\n    return eval(value)\n", encoding="utf-8")
        marker.write_text('{"kind":"owned-deployment-acceptance"}', encoding="utf-8")
        packages = {name: version(name) for name in ("hunterqa-ai", "playwright", "botocore", "PyJWT", "cryptography", "dnspython", "waitress", "semgrep")}
        for name in ("semgrep", "clang", "gdb", "afl-fuzz"):
            if shutil.which(name) is None:
                raise ValueError("Missing assessment runtime binary: " + name)
        inventory = subprocess.run([sys.executable, "-m", "pip", "list", "--format=json"], capture_output=True, text=True, check=True, timeout=30)  # nosec B603
        installed = {row["name"]: row["version"] for row in json.loads(inventory.stdout)}
        proof = json.loads(distribution("semgrep").read_text("HUNTERQA-DEPENDENCY-PATCH.json"))
        return {"initialized": True, "optional_packages": packages, "installed_python_packages": installed,
            "semgrep_dependency_patch": proof, "tool_binaries_present": True}
    if not marker.is_file() or json.loads(marker.read_text()).get("kind") != "owned-deployment-acceptance":
        raise ValueError("Owned deployment marker missing")
    if phase == "archive":
        before = call("operator-status", "--database", control / "owned-ci/operators.sqlite3")["instance"]
        old_key_digest = hashlib.sha256((control / "owned-ci/session.key").read_bytes()).hexdigest()
        archive = home / "backups/owned.zip"
        result = call("workspace-backup", "--config", config, "--out", archive, "--authorized")
        call("workspace-backup-check", "--backup", archive, "--sha256", result["sha256"])
        data.rename(home / "retired-data")
        data.mkdir(mode=0o700)
        (control / "owned-ci").rename(control / "retired-owned-ci")
        result = call("workspace-restore", "--backup", archive, "--sha256", result["sha256"], "--workspace-id", "owned-ci", "--root", data, "--authorized")
        assert result["accounts_disabled"] and result["sessions_revoked"]
        assert hashlib.sha256((control / "owned-ci/session.key").read_bytes()).hexdigest() != old_key_digest
        call("operator-update", "--database", control / "owned-ci/operators.sqlite3", "--username", "admin", "--enable", "--reset-password", "--authorized", password=RENEWED)
        call("operator-update", "--database", control / "owned-ci/operators.sqlite3", "--username", "analyst", "--enable", "--reset-password", "--authorized", password=RENEWED)
        call("operator-mfa-enroll", "--database", control / "owned-ci/operators.sqlite3", "--key-file", control / "owned-ci/auth.key", "--username", "admin", "--secret-stdin", "--authorized", input_text=RENEWED_FACTOR)
        assert call("operator-status", "--database", control / "owned-ci/operators.sqlite3")["instance"] != before
        call("workspace-check", "--config", config)
        return {"archive_verified": True, "restored_original_paths": True, "keys_rotated": True, "credentials_renewed": True}
    return verify_http(data, restored=phase == "restored")


def verify_http(data, *, restored):
    base = "http://127.0.0.1:" + str(int(os.environ["HUNTERQA_PORT"]))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), LocalRedirect(), urllib.request.HTTPCookieProcessor(CookieJar()))

    def request(path, values=None):
        payload = urllib.parse.urlencode(values).encode() if values is not None else None
        try:
            with opener.open(base + path, data=payload, timeout=15) as response:
                return response.status, response.read(2_000_000), response.geturl()
        except urllib.error.HTTPError as error:
            return error.code, error.read(65536), error.geturl()

    def csrf(raw):
        return re.search(rb'name="csrf_token" value="([A-Za-z0-9_-]+)"', raw).group(1).decode()

    _, raw, _ = request("/login")
    status, _, _ = request("/login", {"username": "analyst", "password": RENEWED if restored else PASSWORD, "csrf_token": csrf(raw)})
    assert status == 200
    if not restored:
        _, raw, _ = request("/projects")
        assert request("/projects", {"name": "Owned deployment project", "path": str(data / "assessments/project"), "csrf_token": csrf(raw)})[0] == 200
        _, raw, _ = request("/projects")
        assert request("/projects/1/scans", {"csrf_token": csrf(raw), "authorized": "yes", "authorization_text": "I AM AUTHORIZED TO SCAN THIS PROJECT"})[0] == 200
        end = time.monotonic() + 75
        while True:
            status, raw, _ = request("/api/scans/1/status")
            scan = json.loads(raw)
            if scan["status"] == "completed":
                break
            if scan["status"] == "failed":
                raise RuntimeError("Owned source worker failed: " + str(scan.get("error", ""))[:2000])
            assert time.monotonic() < end
            time.sleep(0.5)
    assert request("/scans/1/export.json")[0] == 200
    assert request("/scans/1/report")[0] == 200
    if not restored:
        request("/logout", {"csrf_token": csrf(request("/projects")[1])})
        _, raw, _ = request("/login")
        assert request("/login", {"username": "viewer", "password": PASSWORD, "csrf_token": csrf(raw)})[0] == 200
        token = csrf(request("/projects")[1])
        assert request("/projects", {"name": "Denied", "path": str(data / "assessments/project"), "csrf_token": token})[0] == 403
    else:
        request("/logout", {"csrf_token": csrf(request("/projects")[1])})
        _, raw, _ = request("/login")
        assert request("/login", {"username": "viewer", "password": PASSWORD, "csrf_token": csrf(raw)})[0] == 401
    from playwright.sync_api import sync_playwright, expect
    with sync_playwright() as driver:
        browser = driver.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base + "/") else route.abort())
            page.goto(base + "/projects")
            page.get_by_label("Username", exact=True).fill("admin")
            page.get_by_label("Password", exact=True).fill(RENEWED if restored else PASSWORD)
            page.get_by_role("button", name="Sign in", exact=True).click()
            expect(page.get_by_role("heading", name="Verify your sign-in")).to_be_visible()
            # A correct password still grants no API access before the second factor.
            assert page.request.get(base + "/api/scans/1/status").status == 401
            from hunterqa.identity_policy import totp
            page.get_by_label("Verification code", exact=True).fill(totp(RENEWED_FACTOR if restored else FACTOR))
            page.get_by_role("button", name="Verify sign-in", exact=True).click()
            page.goto(base + "/scans/1/report")
            expect(page.get_by_text("Workspace analysis summary", exact=False)).to_be_visible()
            page.get_by_role("button", name="Sign out", exact=True).click()
            expect(page.get_by_role("heading", name="Sign in to HunterQA")).to_be_visible()
        finally:
            browser.close()
    with closing(sqlite3.connect(data / "state/dashboard.sqlite3")) as db:
        assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] > 0
        assert db.execute("SELECT COUNT(*) FROM findings WHERE engine='semgrep'").fetchone()[0] > 0
    assert PASSWORD.encode() not in (data.parent / "control/owned-ci/operators.sqlite3").read_bytes()
    return {"local_login": True, "admin_mfa_verified": True, "pre_mfa_api_denied": True, "source_scan_completed": True, "export_and_report": True,
        "rbac_denial_verified": True, "real_chromium_login_report_logout": True, "external_idp_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True, choices=("health", "init", "verify", "archive", "restored"))
    parser.add_argument("--wait", type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.wait <= 30:
        raise ValueError("Health wait must be 0..30 seconds")
    result = health(args.wait) if args.phase == "health" else acceptance(args.phase)
    result.update(phase=args.phase, production_ready=False)
    print(json.dumps(result, sort_keys=True))
    if args.phase == "health" and not result["healthy"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
