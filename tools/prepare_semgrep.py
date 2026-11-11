"""Reproducible dependency-only repair of one verified upstream Semgrep wheel.

No vendor Python/native payload or license is changed. This is a local compatibility
patch, not an upstream release; exercise the scanning contract and audit the result.
"""
import argparse
import base64
import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

BASE = "1.185.0"
LOCAL = BASE + "+hunterqa.1"
DEPENDENCIES = {
    "mcp==1.29.0": "mcp==1.30.0",
    "opentelemetry-api~=1.37.0": "opentelemetry-api==1.45.2",
    "opentelemetry-sdk~=1.37.0": "opentelemetry-sdk==1.45.2",
    "opentelemetry-exporter-otlp-proto-http~=1.37.0": "opentelemetry-exporter-otlp-proto-http==1.45.2",
    "opentelemetry-instrumentation-requests~=0.58b0": "opentelemetry-instrumentation-requests==0.66b2",
    "opentelemetry-instrumentation-threading~=0.58b0": "opentelemetry-instrumentation-threading==0.66b2",
}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def patch_wheel(source, output_dir, expected_sha256):
    source, output_dir = Path(source), Path(output_dir)
    if source.is_symlink() or not source.name.startswith("semgrep-" + BASE + "-") or sha(source) != expected_sha256:
        raise ValueError("Upstream wheel name or SHA-256 differs")
    old_info, new_info = "semgrep-" + BASE + ".dist-info/", "semgrep-" + LOCAL + ".dist-info/"
    destination = output_dir / source.name.replace("semgrep-" + BASE + "-", "semgrep-" + LOCAL + "-", 1)
    with zipfile.ZipFile(source) as original:
        lines = original.read(old_info + "METADATA").decode("utf-8").splitlines()
        seen, changed = set(), []
        if lines.count("Version: " + BASE) != 1:
            raise ValueError("Unexpected supplier metadata version")
        for line in lines:
            if line == "Version: " + BASE:
                line = "Version: " + LOCAL
            elif line.startswith("Requires-Dist: ") and line[15:] in DEPENDENCIES:
                requirement = line[15:]
                if requirement in seen:
                    raise ValueError("Duplicate supplier dependency")
                seen.add(requirement)
                line = "Requires-Dist: " + DEPENDENCIES[requirement]
            changed.append(line)
        if seen != set(DEPENDENCIES):
            raise ValueError("Supplier dependency metadata changed; review before building")
        proof = {"upstream_package": "semgrep", "upstream_version": BASE, "local_version": LOCAL,
            "upstream_wheel_sha256": expected_sha256, "vendor_payload_changed": False,
            "dependency_replacements": DEPENDENCIES, "upstream_supported_patch": False}
        records = []
        with destination.open("xb") as file:
            with zipfile.ZipFile(file, "w", compression=zipfile.ZIP_DEFLATED) as target:
                def write(name, raw, info=None):
                    entry = copy.copy(info) if info is not None else zipfile.ZipInfo(name)
                    entry.filename = name
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    target.writestr(entry, raw)
                    records.append([name, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("="), str(len(raw))])

                for info in original.infolist():
                    if info.is_dir() or info.filename in {old_info + "RECORD", old_info + "RECORD.jws", old_info + "RECORD.p7s"}:
                        continue
                    name = info.filename.replace(old_info, new_info, 1) if info.filename.startswith(old_info) else info.filename
                    if name.startswith("semgrep-" + BASE + ".data/"):
                        name = name.replace("semgrep-" + BASE + ".data/", "semgrep-" + LOCAL + ".data/", 1)
                    raw = ("\n".join(changed) + "\n").encode() if info.filename == old_info + "METADATA" else original.read(info)
                    write(name, raw, info)
                write(new_info + "HUNTERQA-DEPENDENCY-PATCH.json", json.dumps(proof, sort_keys=True).encode())
                record = io.StringIO(newline="")
                csv.writer(record).writerows(records + [[new_info + "RECORD", "", ""]])
                target.writestr(new_info + "RECORD", record.getvalue().encode())
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()
    directory = Path(args.out_dir)
    if not directory.is_absolute() or directory.exists():
        raise ValueError("Use a new absolute wheel directory")
    directory.mkdir(mode=0o755)
    with tempfile.TemporaryDirectory(prefix="upstream-wheel-", dir=directory) as temporary:
        subprocess.run([sys.executable, "-m", "pip", "download", "--disable-pip-version-check", "--no-deps",
            "--only-binary=:all:", "--dest", temporary, "semgrep==" + BASE], check=True, timeout=180)  # nosec B603
        wheels = list(Path(temporary).glob("*.whl"))
        if len(wheels) != 1:
            raise ValueError("Expected exactly one supplier wheel")
        # The independently fetched official digest also rejects altered mirrors.
        url = "https://pypi.org/pypi/semgrep/" + BASE + "/json"
        with urllib.request.urlopen(url, timeout=10) as response:  # nosec B310
            raw = response.read(2000001)
        if len(raw) > 2000000:
            raise ValueError("Supplier metadata exceeds bounds")
        metadata = json.loads(raw)
        matches = [row["digests"]["sha256"] for row in metadata["urls"] if row["filename"] == wheels[0].name]
        if len(matches) != 1:
            raise ValueError("Supplier wheel is missing from official metadata")
        result = patch_wheel(wheels[0], directory, matches[0])
        print(json.dumps({"wheel": result.name, "sha256": sha(result), "dependency_only_patch": True}))


if __name__ == "__main__":
    main()
