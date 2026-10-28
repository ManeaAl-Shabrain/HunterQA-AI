import json
import subprocess
import zipfile

from tools.build_release import build


def test_builder_excludes_runtime_data_and_private_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    for name, text in [
        ("hunterqa/core.py", "answer = 42\n"),
        ("zeroscope/__init__.py", "from hunterqa import create_app\n"),
        ("tests/test_basic.py", "def test_ok(): assert True\n"),
        ("hunterqa/.env", "TOKEN=SECRET\n"),
        ("instance/cache.sqlite3", "sensitive"),
        ("reports/findings.json", "local results"),
    ]:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    output = tmp_path / "release.zip"
    manifest = build(repo, output)
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        assert "HunterQA-AI/hunterqa/core.py" in names
        assert "HunterQA-AI/zeroscope/__init__.py" in names
        assert "HunterQA-AI/tests/test_basic.py" in names
        assert "HunterQA-AI/hunterqa/.env" not in names
        assert "HunterQA-AI/instance/cache.sqlite3" not in names
        assert "HunterQA-AI/reports/findings.json" not in names
        saved = json.loads(archive.read("HunterQA-AI/RELEASE_MANIFEST.json"))
    assert saved == manifest


def test_builder_refuses_existing_output(tmp_path):
    import pytest
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    output = tmp_path / "exists.zip"
    output.write_bytes(b"do not overwrite")
    with pytest.raises(FileExistsError):
        build(repo, output)
    assert output.read_bytes() == b"do not overwrite"
