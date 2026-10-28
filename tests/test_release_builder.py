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
        ("labs/research-lab/verification/sanitizer_parser.py", "def parse_sanitizer_log(s): return {}\n"),
        ("labs/research-lab/verification/local_evidence.json", '{"secret":"private"}'),
        ("LICENSE", "MIT License\n"),
        ("SECURITY.md", "Security policy\n"),
        ("zero to start.md", "Public setup guide\n"),
        (".github/workflows/release-qa.yml", "name: Test CI\n"),
        ("hunterqa/.env", "TOKEN=SECRET\n"),
        ("instance/cache.sqlite3", "sensitive"),
        ("reports/findings.json", "local results"),
    ]:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    # Require the project version without including fake package metadata in
    # the expected public archive fixtures.
    (repo / "pyproject.toml").write_text(
        '[project]\\nname = "hunterqa-ai"\\nversion = "1.2.0"\\n'.replace('\\n', '\n')
    )
    output = tmp_path / "release.zip"
    manifest = build(repo, output)
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        assert "HunterQA-AI/hunterqa/core.py" in names
        assert "HunterQA-AI/zeroscope/__init__.py" in names
        assert "HunterQA-AI/tests/test_basic.py" in names
        assert "HunterQA-AI/labs/research-lab/verification/sanitizer_parser.py" in names
        assert "HunterQA-AI/labs/research-lab/verification/local_evidence.json" not in names
        assert "HunterQA-AI/LICENSE" in names
        assert "HunterQA-AI/SECURITY.md" in names
        assert "HunterQA-AI/zero to start.md" in names
        assert "HunterQA-AI/.github/workflows/release-qa.yml" in names
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
