"""Conservative static safety gate for untrusted AI patch proposals.

The gate parses Python candidates without executing or importing them.
A non-blocking verdict is NOT a statement that a proposed patch is safe.
"""

from __future__ import annotations

import ast
from pathlib import Path

BLOCKED_CALLS = {
    "eval": "Dynamic expression evaluation is not sandboxed by removing builtins",
    "builtins.eval": "Dynamic expression evaluation remains unsafe",
    "exec": "Dynamic code execution is not an acceptable remediation",
    "builtins.exec": "Dynamic code execution is not an acceptable remediation",
    "compile": "Dynamic code compilation needs separate review",
    "builtins.compile": "Dynamic code compilation needs separate review",
    "pickle.loads": "Unsafe deserialization of untrusted pickle input",
    "pickle.load": "Unsafe deserialization of untrusted pickle input",
    "cPickle.loads": "Unsafe deserialization of untrusted pickle input",
    "dill.loads": "Unsafe deserialization via dill",
    "cloudpickle.loads": "Unsafe deserialization via cloudpickle",
    "marshal.loads": "Untrusted marshal deserialization",
    "yaml.load": "Potentially unsafe YAML loader",
    "os.system": "Shell command execution",
    "os.popen": "Shell command execution",
    "subprocess.getoutput": "Shell command execution",
    "subprocess.getstatusoutput": "Shell command execution",
}
SHELL_CALLS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
    "run", "Popen", "call", "check_call", "check_output",
}
DYNAMIC_LOOKUP = {"getattr", "globals", "locals", "__import__"}


def _callee_name(expr: ast.expr) -> str:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        parent = _callee_name(expr.value)
        return f"{parent}.{expr.attr}" if parent else expr.attr
    return ""


def _result(verdict: str, reasons: list[str], language: str) -> dict:
    return {
        "verdict": verdict,
        "language": language,
        "blocking": verdict in {"blocked_unsafe", "blocked_invalid"},
        "reasons": sorted(set(reasons))[:12],
        "model_output_executed": False,
        "semantic_correctness_verified": False,
        "security_fix_verified": False,
        "human_review_required": True,
    }


def inspect_patch_line(filename: str, candidate: str) -> dict:
    """Return a conservative verdict on an untrusted single-line proposal.

    Even if the code appears syntactically valid and lacks listed sinks,
    semantic safety is unknown. No code is evaluated or executed.
    """
    language = "python" if Path(filename).suffix.lower() == ".py" else "other"
    if not isinstance(candidate, str) or not candidate.strip():
        return _result("blocked_invalid", ["Empty or invalid replacement"], language)
    if len(candidate) > 500 or "\n" in candidate or "\r" in candidate:
        return _result("blocked_invalid", ["Replacement is not one bounded line"], language)
    if language != "python":
        return _result("manual_review", [
            "Automatic syntax and sink analysis is not supported for this language"
        ], language)

    # The function wrapper permits Python 'return' at the original source line
    # without importing, executing, or evaluating untrusted model output.
    wrapped = "def __hunterqa_candidate__():\n    " + candidate.lstrip() + "\n"
    try:
        parsed = ast.parse(wrapped, mode="exec")
    except (SyntaxError, ValueError) as exc:
        return _result("blocked_invalid", [
            f"Invalid standalone Python statement: {type(exc).__name__}"
        ], language)

    reasons = []
    uncertainties = []
    for node in ast.walk(parsed):
        if not isinstance(node, ast.Call):
            continue
        name = _callee_name(node.func)
        if name in BLOCKED_CALLS:
            reasons.append(f"{name}: {BLOCKED_CALLS[name]}")
        elif name in DYNAMIC_LOOKUP or name.endswith(".getattr"):
            uncertainties.append(f"{name}: dynamic resolution requires manual review")
        elif name in {"loads", "load"}:
            uncertainties.append(
                f"{name}: unqualified deserializer must be resolved in source context"
            )

        if name in SHELL_CALLS:
            if any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            ):
                reasons.append("subprocess shell=True: shell injection risk remains")
            elif any(kw.arg == "shell" for kw in node.keywords):
                uncertainties.append("subprocess shell parameter cannot be verified statically")
        elif name.endswith(".run") or name.endswith(".Popen"):
            if any(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                   and kw.value.value is True for kw in node.keywords):
                reasons.append("shell=True: shell execution requires rejection")
    if reasons:
        return _result("blocked_unsafe", reasons + uncertainties, language)
    return _result(
        "manual_review",
        uncertainties + [
            "Static screening found no listed prohibited call; imports, behavior, "
            "data flow, regressions and security impact remain unverified"
        ],
        language,
    )
