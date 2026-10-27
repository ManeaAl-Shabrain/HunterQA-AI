"""Bounded Python cross-file call graph and trust-boundary review candidates.

Static evidence only: this is not taint analysis or proof of exploitability.
"""
from __future__ import annotations

import ast
import importlib.util
import os
from collections import defaultdict, deque
from pathlib import Path

SKIP = {".git", ".venv", "venv", "__pycache__", "node_modules", "vendor", "instance", "secrets", ".pytest_cache", "dist", "build"}
MAX_FILE_BYTES = 200_000


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _imports(tree, module, is_package):
    aliases = {}
    package = module if is_package else module.rpartition(".")[0]
    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(stmt, ast.ImportFrom):
            try:
                base = importlib.util.resolve_name(
                    "." * stmt.level + (stmt.module or ""), package
                ) if stmt.level else (stmt.module or "")
            except ImportError:
                continue
            for alias in stmt.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{base}.{alias.name}".strip(".")
    return aliases


def _resolve(raw, aliases, module, owner):
    if not raw:
        return None
    first, dot, rest = raw.partition(".")
    if first == "self" and owner and rest:
        return f"{module}.{owner}.{rest}"
    if first == "cls" and owner and rest:
        return f"{module}.{owner}.{rest}"
    if first in aliases:
        return aliases[first] + (dot + rest if rest else "")
    return f"{module}.{raw}"


def _route(node):
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        name = _dotted(decorator.func) or ""
        if name.rpartition(".")[2] not in {"route", "get", "post", "put", "patch", "delete"}:
            continue
        if decorator.args and isinstance(decorator.args[0], ast.Constant):
            url = decorator.args[0].value
            if isinstance(url, str) and url.startswith("/"):
                return url[:200]
    return None


def _body_nodes(fn):
    stack = list(reversed(fn.body))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _operation(name, call):
    if name in {"builtins.eval", "builtins.exec", "eval", "exec"}:
        return "dynamic_code_execution", "CWE-95"
    if name == "os.system":
        return "shell_execution", "CWE-78"
    if name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"}:
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return "subprocess_shell_true", "CWE-78"
    if name in {"pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load", "yaml.unsafe_load"}:
        return "unsafe_deserialization", "CWE-502"
    return None


def _module_name(root, path):
    rel = path.relative_to(root)
    bits = list(rel.with_suffix("").parts)
    is_package = bits[-1] == "__init__"
    if is_package:
        bits.pop()
    if (root / "__init__.py").is_file():
        bits.insert(0, root.name)
    return ".".join(bits), is_package


def build_trust_graph(root: Path, max_files: int = 200, max_paths: int = 100):
    """Analyze authorized local Python files, with no imports or code execution."""
    root = Path(root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Expected local source directory")
    max_files = min(max(1, int(max_files)), 500)
    max_paths = min(max(1, int(max_paths)), 500)
    paths = []
    skipped = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not d.startswith(".") and not (base / d).is_symlink())
        for filename in sorted(files):
            path = base / filename
            if path.suffix != ".py" or path.is_symlink():
                continue
            try:
                size = path.stat().st_size
            except OSError:
                skipped += 1
                continue
            if size > MAX_FILE_BYTES:
                skipped += 1
            elif len(paths) < max_files:
                paths.append(path)
            else:
                skipped += 1
    funcs = {}
    parsed = []
    errors = []
    for path in paths:
        file = path.relative_to(root).as_posix()
        module, is_package = _module_name(root, path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=file)
        except (SyntaxError, OSError, UnicodeError):
            errors.append(file)
            continue
        aliases = _imports(tree, module, is_package)
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs[f"{module}.{statement.name}"] = (statement, file, module, None, aliases)
            elif isinstance(statement, ast.ClassDef):
                for method in statement.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        funcs[f"{module}.{statement.name}.{method.name}"] = (method, file, module, statement.name, aliases)
        parsed.append(file)
    nodes = []
    edge_candidates = []
    for identifier, (fn, file, module, owner, aliases) in sorted(funcs.items()):
        ingress, operations = [], []
        for node in _body_nodes(fn):
            if isinstance(node, ast.Attribute):
                raw = _dotted(node)
                resolved = _resolve(raw, aliases, module, owner)
                if raw and (raw.startswith("request.") or (resolved or "").startswith("flask.request.")):
                    ingress.append({"line": node.lineno, "kind": "request_input_reference"})
            elif isinstance(node, ast.Call):
                raw = _dotted(node.func)
                if not raw:
                    continue
                callee = _resolve(raw, aliases, module, owner)
                if callee in funcs:
                    edge_candidates.append({"caller": identifier, "callee": callee, "line": node.lineno, "file": file})
                resolved = callee or ""
                bare_name = raw if raw in {"eval", "exec"} else resolved
                op = _operation(bare_name, node)
                if op:
                    operations.append({"kind": op[0], "cwe_candidate": op[1], "file": file, "line": node.lineno})
        ingress = list({(r["line"], r["kind"]): r for r in ingress}.values())
        nodes.append({"id": identifier, "file": file, "line": fn.lineno, "route": _route(fn),
                      "input_references": sorted(ingress, key=lambda i: i["line"]), "sensitive_operations": operations})
    edges = sorted(edge_candidates, key=lambda e: (e["caller"], e["line"], e["callee"]))[:3000]
    graph = defaultdict(list)
    for edge in edges:
        graph[edge["caller"]].append(edge["callee"])
    by_id = {node["id"]: node for node in nodes}
    review_paths = []
    for entry in nodes:
        if entry["route"] is None:
            continue
        queue = deque([(entry["id"], [entry["id"]])])
        visited = {entry["id"]}
        while queue and len(review_paths) < max_paths:
            current, chain = queue.popleft()
            target = by_id[current]
            for operation in target["sensitive_operations"]:
                review_paths.append({"entrypoint": entry["id"], "route": entry["route"],
                                     "call_chain": chain, "operation": operation,
                                     "request_reference_observed": any(by_id[i]["input_references"] for i in chain),
                                     "taint_flow_confirmed": False,
                                     "verification_status": "requires_source_review"})
                if len(review_paths) >= max_paths:
                    break
            if len(chain) >= 5:
                continue
            for nxt in graph[current]:
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, chain + [nxt]))
    return {"engine": "python_static_call_graph", "project": "HunterQA AI", "files_analyzed": len(parsed),
            "files_skipped": skipped, "parse_errors": errors[:30], "functions": len(nodes),
            "nodes": nodes, "edges": edges, "review_paths": review_paths,
            "analysis_limitations": "Python only, resolved direct calls, bounded depth; no argument/taint propagation.",
            "zero_days_confirmed": 0}


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser(description="Local Python call graph research")
    parser.add_argument("--project", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build_trust_graph(args.project), indent=2))
