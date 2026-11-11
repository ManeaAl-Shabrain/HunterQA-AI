"""Metadata-only supplier repair, source hash, license, executable and RECORD checks."""
import base64
import csv
import hashlib
import io
import json
import zipfile

import pytest

from tools.prepare_semgrep import BASE, LOCAL, DEPENDENCIES, patch_wheel, sha


def supplier(tmp_path):
    path = tmp_path / ("semgrep-" + BASE + "-py3-none-any.whl")
    metadata = "Metadata-Version: 2.3\nName: semgrep\nVersion: " + BASE + "\n"
    metadata += "".join("Requires-Dist: " + item + "\n" for item in DEPENDENCIES)
    metadata += "\nOwned synthetic wheel fixture\n"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("semgrep-" + BASE + ".dist-info/METADATA", metadata)
        archive.writestr("semgrep-" + BASE + ".dist-info/RECORD", "")
        archive.writestr("semgrep-" + BASE + ".dist-info/LICENSE", "Owned fixture license content")
        binary = zipfile.ZipInfo("semgrep/bin/semgrep-core")
        binary.create_system = 3
        binary.external_attr = 0o100755 << 16
        archive.writestr(binary, b"owned executable fixture; never run")
        archive.writestr("semgrep/example.py", b"# owned payload\n")
    output = tmp_path / "output"
    output.mkdir()
    return path, output


def test_patch_preserves_vendor_payload_license_mode_and_rebuilds_record(tmp_path):
    source, directory = supplier(tmp_path)
    result = patch_wheel(source, directory, sha(source))
    assert LOCAL in result.name
    prefix = "semgrep-" + LOCAL + ".dist-info/"
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(result) as repaired:
        for name in ("semgrep/example.py", "semgrep/bin/semgrep-core"):
            assert repaired.read(name) == original.read(name)
            assert repaired.getinfo(name).external_attr == original.getinfo(name).external_attr
        assert repaired.read(prefix + "LICENSE") == original.read("semgrep-" + BASE + ".dist-info/LICENSE")
        metadata = repaired.read(prefix + "METADATA").decode()
        assert "Version: " + LOCAL in metadata
        assert all("Requires-Dist: " + value in metadata for value in DEPENDENCIES.values())
        proof = json.loads(repaired.read(prefix + "HUNTERQA-DEPENDENCY-PATCH.json"))
        assert proof["upstream_wheel_sha256"] == sha(source) and proof["vendor_payload_changed"] is False
        for name, digest, length in csv.reader(io.StringIO(repaired.read(prefix + "RECORD").decode())):
            if name.endswith("/RECORD"):
                continue
            raw = repaired.read(name)
            assert len(raw) == int(length)
            assert digest == "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def test_wrong_supplier_digest_refused_before_output(tmp_path):
    source, directory = supplier(tmp_path)
    with pytest.raises(ValueError, match="SHA-256"):
        patch_wheel(source, directory, "0" * 64)
    assert not list(directory.iterdir())


def test_changed_supplier_metadata_requires_review(tmp_path):
    source, directory = supplier(tmp_path)
    with zipfile.ZipFile(source) as original:
        rows = {info.filename: original.read(info) for info in original.infolist()}
    name = "semgrep-" + BASE + ".dist-info/METADATA"
    rows[name] = rows[name].replace(b"mcp==1.29.0", b"mcp==1.29.1")
    with zipfile.ZipFile(source, "w") as original:
        for name, raw in rows.items():
            original.writestr(name, raw)
    with pytest.raises(ValueError, match="metadata changed"):
        patch_wheel(source, directory, sha(source))
    assert not list(directory.iterdir())
