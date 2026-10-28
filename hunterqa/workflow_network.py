"""Durable request-intent journals; logging an intent does not prove delivery."""
from __future__ import annotations

import hashlib
import json
import os
from urllib.parse import urlsplit

from .bounty import _approved_file
from .engagement import digest, utcnow
from .source_files import read_bounded


def journal_targets(step, binding):
    if step["tool"] not in ("authorization-matrix", "web-canary-check"):
        return step["targets"]
    from .bounty import _read_json
    raw = read_bounded(_approved_file(binding["file"]), 65_536)
    if hashlib.sha256(raw).hexdigest() != binding["file_sha256"]:
        raise ValueError("Assessment manifest evidence changed after review")
    data = _read_json(binding["file"], 65_536)
    targets = ([case["url"] for case in data["cases"]] if step["tool"] == "authorization-matrix"
               else [check["url"] for check in data["checks"] for _ in range(2)])
    if not 1 <= len(targets) <= step["requests"] or not set(targets) <= set(step["targets"]):
        raise ValueError("Access matrix journal exceeds reviewed scope")
    return targets


def journal_queries(step, binding):
    if step["tool"] != "web-canary-check":
        return None
    from .bounty import _read_json
    from .web_canaries import request_digest, variants
    journal_targets(step, binding)
    data = _read_json(binding["file"], 65_536)
    return [request_digest(check["url"], query) for check in data["checks"] for _, query in variants(check)]


class NetworkJournal:
    def __init__(self, path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.stream = os.fdopen(fd, "wb")
        self.previous, self.seq = "0" * 64, 0

    def append(self, kind, target, method, **details):
        self.seq += 1
        value = {"seq": self.seq, "time": utcnow().isoformat(), "kind": kind,
                 "target_sha256": digest(target), "method": method,
                 "details": details, "previous": self.previous}
        self.previous = digest(value)
        self.stream.write((json.dumps({"value": value, "sha256": self.previous}) + "\n").encode())
        self.stream.flush()
        os.fsync(self.stream.fileno())

    def close(self):
        self.stream.close()


def inspect_network(path, targets, *, discovery_policy=None, request_budget=None, transport="http", request_digests=None):
    if transport not in ("http", "tcp", "aws-query"):
        raise ValueError("Unsupported journal transport")
    if not path.exists():
        return {"sha256": None, "intents": 0, "responses": 0, "connections": 0, "incomplete_tail": False, "records": []}
    raw = read_bounded(_approved_file(path), 65_536)
    lines = raw.splitlines(keepends=True)
    incomplete = bool(lines and not lines[-1].endswith(b"\n"))
    if incomplete:
        lines.pop()
    dynamic = discovery_policy is not None
    maximum = request_budget if dynamic else len(targets)
    if type(maximum) is not int or not 1 <= maximum <= (20 if dynamic else 40):
        raise ValueError("Invalid journal request reservation")
    if len(lines) > 2 * maximum:
        raise ValueError("Network journal exceeds target reservation")
    def origin(url):
        parts = urlsplit(url)
        return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    origins = {origin(target) for target in targets} if dynamic else set()
    admitted = set()
    previous, records, intents, responses, connections, pending = "0" * 64, [], 0, 0, 0, None
    for index, line in enumerate(lines, start=1):
        row = json.loads(line)
        value = row["value"]
        if value["seq"] != index or value["previous"] != previous or digest(value) != row["sha256"]:
            raise ValueError("Network journal hash chain mismatch")
        previous = row["sha256"]
        methods = {"tcp": ("TCP",), "aws-query": ("POST",), "http": ("HEAD", "GET")}
        if value["method"] not in methods[transport]:
            raise ValueError("Network journal method mismatch")
        if value["kind"] == "intent":
            if pending is not None or intents >= maximum:
                raise ValueError("Network intent order/scope mismatch")
            if dynamic:
                url = value["details"].get("target_url")
                if not isinstance(url, str) or len(url) > 1024 or value["method"] != "GET":
                    raise ValueError("Invalid discovery request intent")
                discovery_policy.authorize_url(url, "GET")
                if origin(url) not in origins or value["target_sha256"] != digest(url) or url in admitted:
                    raise ValueError("Discovery intent exceeds reviewed origin/scope")
                if intents == 0 and url not in targets:
                    raise ValueError("Discovery must begin with a reviewed seed")
                admitted.add(url)
            elif value["target_sha256"] != digest(targets[intents]):
                raise ValueError("Network intent order/scope mismatch")
            if request_digests is not None and (len(request_digests) != len(targets)
                    or value["details"].get("request_sha256") != request_digests[intents]):
                raise ValueError("Query request does not match the reviewed fixed probe")
            intents += 1
            pending = (value["target_sha256"], value["method"])
        elif value["kind"] in ("response", "error", "connect-outcome"):
            if pending is None or (value["target_sha256"], value["method"]) != pending:
                raise ValueError("Network outcome lacks a matching intent")
            pending = None
            if transport == "tcp" and value["kind"] == "response":
                raise ValueError("TCP journals cannot assert HTTP responses")
            if value["kind"] == "connect-outcome":
                if transport != "tcp" or value["details"].get("outcome") not in ("connected", "refused", "timeout", "unreachable"):
                    raise ValueError("Invalid TCP outcome")
                connections += 1
            if value["kind"] == "response":
                status = value["details"].get("status")
                if type(status) is not int or not 100 <= status <= 999:
                    raise ValueError("Invalid recorded HTTP status")
                responses += 1
        else:
            raise ValueError("Unknown network journal event")
        records.append(value)
    return {"sha256": hashlib.sha256(raw).hexdigest(), "intents": intents,
            "responses": responses, "connections": connections, "incomplete_tail": incomplete, "records": records}
