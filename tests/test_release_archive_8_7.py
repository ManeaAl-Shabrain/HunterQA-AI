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
    return repo


def test_valid_release_manifest(tmp_path):
    repo = _repo(tmp_path)
    path = tmp_path / "release.zip"
    build(repo, path)
    assert verify_archive(path) == 1


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
