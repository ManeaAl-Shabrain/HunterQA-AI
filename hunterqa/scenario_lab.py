"""Versioned, reproducible owned HTTP/SQLite/callback fixtures; no remote target."""
from contextlib import contextmanager
from datetime import timedelta
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import sqlite3
import socketserver
import threading
import time
from urllib.parse import parse_qs, urlsplit
import urllib.request

from .engagement import utcnow

MARKER = "HUNTERQA_CANARY_0123456789abcdef"
SECRET = "Owned-scenario-session-0123456789"  # public synthetic fixture only
VERSION = "owned-expansion-1.0"


@contextmanager
def serve():
    observed, uploads, requests = set(), {}, []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, body=b"", mime="text/plain", headers=()):
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parts = urlsplit(self.path)
            query = parse_qs(parts.query)
            with lock:
                requests.append(("GET", parts.path))
            if self.server is collector:
                token = query.get("token", [""])[0]
                if not re.fullmatch(r"[a-f0-9]{32}", token):
                    return self.respond(400)
                if parts.path == "/receive":
                    with lock:
                        observed.add(token)
                    return self.respond(200, b"recorded")
                if parts.path == "/read":
                    with lock:
                        present = token in observed
                    return self.respond(200, json.dumps({"token": token, "observed": present}).encode(), "application/json")
                return self.respond(404)
            if parts.path.startswith("/boolean-") or parts.path == "/safe":
                value = query.get("id", [""])[0]
                with sqlite3.connect(":memory:") as db:
                    db.execute("CREATE TABLE items(id INTEGER,name TEXT,marker TEXT)")
                    db.execute("INSERT INTO items VALUES(1,'seed',?)", (MARKER,))
                    if parts.path == "/safe":
                        rows = db.execute("SELECT marker FROM items WHERE name=?", (value,)).fetchall()
                    else:
                        context = parts.path.removeprefix("/boolean-")
                        expression = value if context == "numeric" else ("'" + value + "'") if context == "single-quoted" else ('"' + value + '"')
                        try:
                            # Deliberately vulnerable, isolated in-memory fixture.
                            rows = db.execute("SELECT marker FROM items WHERE " + ("id=" if context == "numeric" else "name=") + expression).fetchall()  # nosec B608
                        except sqlite3.Error:
                            rows = []
                return self.respond(200, MARKER.encode() if rows else b"missing")
            if parts.path == "/timing":
                value = query.get("id", [""])[0]
                if "SLEEP(1)" in value or "pg_sleep(1)" in value or "00:00:01" in value:
                    time.sleep(1)
                return self.respond(200, b"synthetic latency fixture")
            if parts.path == "/fetch":
                value = query.get("url", [""])[0]
                expected = collector_base + "/receive?token="
                if not value.startswith(expected) or not re.fullmatch(r"[a-f0-9]{32}", value[len(expected):]):
                    return self.respond(400)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(value, timeout=2) as response:
                    response.read(32)
                return self.respond(200, b"fetched owned witness")
            if parts.path.startswith("/uploads/"):
                token = parts.path.removeprefix("/uploads/").removesuffix(".txt")
                with lock:
                    value = uploads.get(token)
                return self.respond(200 if value is not None else 404, value or b"")
            if parts.path == "/resource":
                return self.respond(200, b"owned tenant-a resource") if self.headers.get("X-Actor") == "owner" else self.respond(403)
            if parts.path == "/session-start":
                return self.respond(200, b"session issued", headers=[("Set-Cookie", "owned_session=" + SECRET + "; Path=/; HttpOnly; SameSite=Strict")])
            if parts.path == "/session-state":
                return self.respond(200, b"session retained") if ("owned_session=" + SECRET) in self.headers.get("Cookie", "") else self.respond(403)
            if parts.path == "/slow":
                self.send_response(200)
                self.send_header("Content-Length", "20")
                self.end_headers()
                try:
                    for _ in range(20):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.1)
                except OSError:
                    pass
                return
            if parts.path == "/app":
                body = ('<html><body><input id="value"><button id="apply">Apply</button><div id="state">Waiting</div>'
                    '<script>document.querySelector("#apply").onclick=async()=>{const r=await fetch("/action",{method:"POST",body:document.querySelector("#value").value});'
                    'document.querySelector("#state").textContent=(localStorage.getItem("owned_token")==="' + SECRET + '"?"Session ":"Anonymous ")+await r.text();'
                    'const a=document.createElement("a");a.href="/resource";a.textContent="Resource";document.body.append(a);};</script></body></html>').encode()
                return self.respond(200, body, "text/html")
            if parts.path.startswith("/xss-"):
                value = query.get("value", [""])[0]
                if parts.path == "/xss-dom":
                    body = '<div id="sink"></div><script>document.querySelector("#sink").innerHTML=decodeURIComponent(location.hash.slice(1));</script>'
                elif parts.path == "/xss-double":
                    body = '<input value="' + value + '">'
                elif parts.path == "/xss-single":
                    body = "<input value='" + value + "'>"
                else:
                    body = "<div>" + (html.escape(value) if parts.path == "/xss-safe" else value) + "</div>"
                return self.respond(200, body.encode(), "text/html", headers=[("Content-Security-Policy", "script-src 'none'")] if parts.path == "/xss-csp" else [])
            return self.respond(404)

        def do_POST(self):
            parts = urlsplit(self.path)
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 8192:
                return self.respond(413)
            raw = self.rfile.read(length)
            with lock:
                requests.append(("POST", parts.path))
            if parts.path == "/upload":
                match = re.search(rb'filename="hunterqa-([a-f0-9]{32})\.txt"', raw)
                if not match:
                    return self.respond(400)
                token = match[1].decode()
                payload = ("HUNTERQA_UPLOAD_CANARY_" + token).encode()
                if payload not in raw:
                    return self.respond(400)
                with lock:
                    uploads[token] = payload
                return self.respond(201, b"stored inert text")
            if parts.path == "/cleanup":
                token = parse_qs(raw.decode()).get("canary", [""])[0]
                with lock:
                    uploads.pop(token, None)
                return self.respond(200, b"removed")
            if parts.path == "/action":
                if self.headers.get("X-Actor") != "owner" or ("owned_bootstrap=" + SECRET) not in self.headers.get("Cookie", ""):
                    return self.respond(403)
                return self.respond(200, b"Applied")
            return self.respond(404)

    collector = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    backend = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    collector_base = "http://127.0.0.1:" + str(collector.server_port)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (collector, backend)]
    for thread in threads:
        thread.start()
    try:
        yield {"base": "http://127.0.0.1:" + str(backend.server_port), "collector": collector_base,
            "ports": [backend.server_port, collector.server_port], "requests": requests, "uploads": uploads}
    finally:
        for server in (backend, collector):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(5)


def profile(lab):
    return {"program": "Owned expansion fixtures", "platform": "local-lab", "authorization_reference": "Owned local fixture acceptance",
        "acknowledged_authorization": True, "allowed_hosts": ["127.0.0.1"], "allowed_ports": lab["ports"],
        "allowed_paths": ["/"], "methods": ["GET"], "scenario_methods": ["GET", "POST"], "max_requests": 40, "interval_seconds": 0.5,
        "lab_mode": True, "allow_private_network": True, "allow_http": True}


def plan(cases):
    return {"schema_version": 1, "authorization_reference": "Owned local fixture acceptance",
        "expires_at": (utcnow() + timedelta(minutes=30)).isoformat(), "timeout_seconds": 120,
        "max_requests": sum(len(row["steps"]) if row["kind"] == "workflow" else row["request_budget"] if row["kind"] == "browser-journey"
            else 3 if row["kind"] == "ssrf-callback" else 5 * (1 + len(row["script_urls"])) if row["kind"] == "xss-context" else 5 for row in cases),
        "browser_isolated": True, "cases": cases}


def case(kind, lab, *, context="single-quoted"):
    base = {"id": kind, "kind": kind, "owned_test_endpoint": True, "actor": "anonymous"}
    if kind == "sqli-boolean":
        return base | {"url": lab["base"] + "/boolean-" + context, "parameter": "id", "context": context, "canary_marker": MARKER}
    if kind == "sqli-timing":
        return base | {"url": lab["base"] + "/timing", "parameter": "id", "dialect": "mysql", "single_row_fixture": True}
    if kind == "ssrf-callback":
        return base | {"url": lab["base"] + "/fetch", "parameter": "url", "collector_actor": "anonymous",
            "receive_url": lab["collector"] + "/receive", "read_url": lab["collector"] + "/read"}
    if kind == "upload-canary":
        return base | {"url": lab["base"] + "/upload", "resource_url": lab["base"] + "/uploads/{canary}.txt", "cleanup_url": lab["base"] + "/cleanup"}
    if kind == "browser-journey":
        return base | {"actor": "owner", "url": lab["base"] + "/app", "allowed_requests": [
            {"url": lab["base"] + "/app", "method": "GET", "query_keys": []},
            {"url": lab["base"] + "/action", "method": "POST", "query_keys": []}], "request_budget": 5,
            "actions": [{"action": "fill", "selector": "#value", "value": "owned input"},
                {"action": "click", "selector": "#apply", "value": ""},
                {"action": "assert-text", "selector": "#state", "value": "Session Applied"},
                {"action": "assert-count", "selector": "a[href]", "value": "1"}]}
    if kind == "workflow":
        def step(actor, url, status, body):
            return {"actor": actor, "url": url, "method": "GET", "query": None, "form": None,
                "expected_status": status, "expected_body_sha256": hashlib.sha256(body).hexdigest() if body is not None else None}
        return {"id": "tenant-workflow", "kind": kind, "owned_test_endpoint": True, "steps": [
            step("owner", lab["base"] + "/resource", 200, b"owned tenant-a resource"),
            step("other", lab["base"] + "/resource", 403, None),
            step("anonymous", lab["base"] + "/resource", 403, None),
            step("session", lab["base"] + "/session-start", 200, b"session issued"),
            step("session", lab["base"] + "/session-state", 200, b"session retained")]}
    raise ValueError("Unknown owned fixture case")


def sessions(lab):
    return {"schema_version": 1, "expires_at": (utcnow() + timedelta(minutes=30)).isoformat(), "actors": {name: {"origin": lab["base"], "headers": {"X-Actor": name},
        "cookies": [{"name": "owned_bootstrap", "value": SECRET, "httpOnly": True, "secure": False, "sameSite": "Strict"}] if name == "owner" else [],
        "local_storage": {"owned_token": SECRET} if name == "owner" else {}} for name in ("owner", "other", "session")}}


def graph(domain):
    proof = hashlib.sha256((VERSION + domain).encode()).hexdigest()
    return {"schema_version": 1, "domain": domain, "collected_at": utcnow().isoformat(), "principals": [
        {"id": "user-a", "tenant": "tenant-a", "enabled": True, "kind": "user"},
        {"id": "group-a", "tenant": "tenant-a", "enabled": True, "kind": "group"}],
        "resources": [{"id": "resource-a", "tenant": "tenant-a"}, {"id": "resource-b", "tenant": "tenant-b"}],
        "memberships": [{"member": "user-a", "group": "group-a", "source_sha256": proof}],
        "grants": [{"principal": "group-a", "resource": "resource-a", "actions": ["read", "administer"], "effect": "allow", "condition": "satisfied", "source_sha256": proof},
            {"principal": "user-a", "resource": "resource-b", "actions": ["read"], "effect": "deny", "condition": "satisfied", "source_sha256": proof}],
        "queries": [{"principal": "user-a", "resource": "resource-a", "action": "read", "expected": "allow"},
            {"principal": "user-a", "resource": "resource-b", "action": "read", "expected": "deny"}],
        "paths": [{"start": "user-a", "target": "resource-a"}]}


@contextmanager
def services():
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            if self.server.protocol == "redis":
                if self.request.recv(64) != b"PING\r\n":
                    return
            self.request.sendall(self.server.banner)

    endpoints, servers, threads = {}, [], []
    try:
        for protocol, banner in (("smtp", b"220 owned Postfix fixture\r\n"), ("ftp", b"220 owned vsFTPd fixture\r\n"), ("redis", b"+PONG\r\n")):
            server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            server.protocol, server.banner = protocol, banner
            servers.append(server)
            endpoints[protocol] = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        yield endpoints
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(5)
