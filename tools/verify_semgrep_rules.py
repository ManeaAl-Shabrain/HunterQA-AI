"""Run the actual optional Semgrep engine on generated synthetic code, never execute it."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "hunterqa" / "rules" / "semgrep.yml"
EXPECTED = {
    "hunterqa.python.dangerous-eval", "hunterqa.python.shell-true",
    "hunterqa.python.unsafe-yaml-load", "hunterqa.python.pickle-loads",
    "hunterqa.python.os-system", "hunterqa.python.requests-insecure-tls",
    "hunterqa.python.unsafe-tempfile", "hunterqa.javascript.innerhtml",
    "hunterqa.javascript.eval", "hunterqa.javascript.child-process-exec",
    "hunterqa.javascript.document-write", "hunterqa.php.unserialize", "hunterqa.php.eval",
}
# These snippets are parser fixtures, not programs to run or recommended patterns.
FIXTURES = {
    "positive.py": """import os, subprocess, yaml, pickle, requests, tempfile
def example(value):
    eval(value)
    subprocess.run(value, shell=True)
    yaml.load(value)
    pickle.loads(value)
    os.system(value)
    requests.get(value, verify=False)
    tempfile.mktemp()
""",
    "negative.py": """import ast, json, subprocess, yaml, requests, tempfile
def example(value):
    ast.literal_eval(value)
    subprocess.run(["echo", value], shell=False)
    yaml.safe_load(value)
    json.loads(value)
    requests.get(value, verify=True)
    tempfile.NamedTemporaryFile()
""",
    "positive.js": """const child_process = require('child_process');
function example(value, element) {
  eval(value);
  child_process.exec(value);
  element.innerHTML = value;
  document.write(value);
}
""",
    "negative.js": """const child_process = require('child_process');
function example(value, element) {
  JSON.parse(value);
  child_process.execFile('echo', [value]);
  element.textContent = value;
}
""",
    "positive.php": "<?php function example($value) { unserialize($value); eval($value); }\n",
    "negative.php": "<?php function example($value) { json_decode($value); }\n",
}


def main():
    executable = shutil.which("semgrep")
    if not executable:
        raise RuntimeError("Install the optional semgrep executable for rule acceptance")
    flags = ["--config", str(RULES), "--metrics=off", "--disable-version-check"]
    subprocess.run([executable, "--validate", *flags], check=True, timeout=120)
    with tempfile.TemporaryDirectory(prefix="hunterqa-rule-qa-") as directory:
        target = Path(directory)
        for name, content in FIXTURES.items():
            (target / name).write_text(content, encoding="utf-8")
        completed = subprocess.run([executable, "scan", "--json", "--quiet",
            "--no-rewrite-rule-ids", *flags, str(target)],
            capture_output=True, text=True, timeout=120, check=True)
        result = json.loads(completed.stdout)
        if result.get("errors"):
            raise ValueError("Semgrep reported fixture or rule errors")
        findings = result.get("results", [])
        if any(Path(row["path"]).name.startswith("negative") for row in findings):
            raise ValueError("Bundled rules flagged a labeled negative fixture")
        found = {row["check_id"] for row in findings}
        if found != EXPECTED:
            raise ValueError(f"Rule coverage mismatch: missing={sorted(EXPECTED-found)}, unexpected={sorted(found-EXPECTED)}")
        print(f"PASS: {len(found)} bundled rules matched synthetic positive fixtures; negative fixtures stayed unflagged")


if __name__ == "__main__":
    main()
