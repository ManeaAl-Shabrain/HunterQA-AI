import hashlib
import json
import subprocess
import zipfile
import pytest

from tools.verify_release_archive import verify_archive
from tools.build_release import build


def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    item = repo / "hunterqa" / "demo.py"
    item.parent.mkdir()
    item.write_text("SAFE = True\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    # Metadata is present for the version-locked builder but untracked in this
    # intentionally single-file test archive.
    (repo / "pyproject.toml").write_text(
        '[project]\\nname = "hunterqa-ai"\\nversion = "1.2.0"\\n'.replace('\\n', '\n')
    )
    return repo


def test_valid_release_manifest(tmp_path):
    repo = _repo(tmp_path)
    path = tmp_path / "release.zip"
    build(repo, path)
    assert verify_archive(path) == 1


def test_windows_shell_scripts_are_packaged_with_linux_line_endings(tmp_path):
    repo = _repo(tmp_path)
    scripts = repo / "tools"
    scripts.mkdir()
    script = scripts / "fixture.sh"
    original = b"#!/bin/sh\r\necho fixture\r\n"
    expected = b"#!/bin/sh\necho fixture\n"
    script.write_bytes(original)
    subprocess.run(["git", "add", "tools/fixture.sh"], cwd=repo, check=True)
    path = tmp_path / "portable.zip"
    build(repo, path)
    assert script.read_bytes() == original
    with zipfile.ZipFile(path) as archive:
        assert archive.read("HunterQA-AI/tools/fixture.sh") == expected
        manifest = json.loads(archive.read("HunterQA-AI/RELEASE_MANIFEST.json"))
        row = next(row for row in manifest["files"] if row["path"] == "tools/fixture.sh")
        assert row["sha256"] == hashlib.sha256(expected).hexdigest()
        assert row["bytes"] == len(expected)
    assert verify_archive(path) == 2


def test_tampered_release_rejected(tmp_path):
    repo = _repo(tmp_path)
    good = tmp_path / "good.zip"
    bad = tmp_path / "bad.zip"
    build(repo, good)
    with zipfile.ZipFile(good) as archive, zipfile.ZipFile(bad, "w") as output:
        for name in archive.namelist():
            body = archive.read(name)
            if name.endswith("demo.py"):
                body = b"CHANGED = True\n"
            output.writestr(name, body)
    with pytest.raises(ValueError, match="mismatch"):
        verify_archive(bad)


def test_unexpected_archive_file_rejected(tmp_path):
    repo = _repo(tmp_path)
    good = tmp_path / "good.zip"
    bad = tmp_path / "bad.zip"
    build(repo, good)
    with zipfile.ZipFile(good) as archive, zipfile.ZipFile(bad, "w") as output:
        for name in archive.namelist():
            output.writestr(name, archive.read(name))
        output.writestr("HunterQA-AI/untracked.txt", "extra")
    with pytest.raises(ValueError, match="Unexpected"):
        verify_archive(bad)
