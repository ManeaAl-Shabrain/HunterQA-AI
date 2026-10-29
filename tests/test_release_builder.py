import json
import subprocess
import zipfile

from tools.build_release import build


def test_builder_packages_only_curated_public_templates(tmp_path):
    repo = tmp_path / "template-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    files = {
        "pyproject.toml": '[project]\nname="hunterqa-ai"\nversion="1.3.0"\n',
        "templates/README.md": "Public template instructions\n",
        "templates/HunterQA-scope-template.json": '{"acknowledged_authorization":false}\n',
        "templates/05-web-application-review.md": "Public web review worksheet\n",
        "templates/06-auth-identity-review.md": "Public identity worksheet\n",
        "templates/HunterQA-identity-review-template.json": '{"schema_version":1,"jwt_samples":[],"oauth_clients":[]}\n',
        "templates/HunterQA-ad-review-template.json": '{"schema_version":1,"collected_at":null}\n',
        "templates/07-active-directory-review.md": "Public AD review worksheet\n",
        "templates/HunterQA-wireless-review-template.json": '{"schema_version":1,"records":[]}\n',
        "templates/08-wireless-review.md": "Public wireless review worksheet\n",
        "templates/HunterQA-cloud-review-template.json": '{"schema_version":1,"records":[]}\n',
        "templates/09-cloud-review.md": "Public cloud review worksheet\n",
        "templates/HunterQA-mobile-review-template.json": '{"schema_version":1,"records":[]}\n',
        "templates/10-mobile-review.md": "Public mobile review worksheet\n",
        "templates/HunterQA-iot-review-template.json": '{"schema_version":1,"records":[]}\n',
        "templates/11-iot-embedded-review.md": "Public IoT review worksheet\n",
        "templates/HunterQA-infrastructure-review-template.json": '{"schema_version":1,"records":[]}\n',
        "templates/12-infrastructure-review.md": "Public infrastructure review worksheet\n",
        "templates/HunterQA-exploit-dev-review-template.json": '{"schema_version":1,"records":[]}\n',
        "templates/13-exploit-development-review.md": "Public exploit-development review worksheet\n",
        "templates/client-filled-profile.json": '{"authorization_reference":"PRIVATE_FIXTURE"}',
        "templates/client-case/findings.json": '{"evidence":"PRIVATE_FIXTURE"}',
    }
    for name, value in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    archive_path = tmp_path / "templates-source.zip"
    manifest = build(repo, archive_path)
    included = {row["path"] for row in manifest["files"]}
    assert "templates/README.md" in included
    assert "templates/HunterQA-scope-template.json" in included
    assert {"templates/05-web-application-review.md", "templates/06-auth-identity-review.md",
            "templates/HunterQA-identity-review-template.json"} <= included
    assert {"templates/HunterQA-ad-review-template.json", "templates/07-active-directory-review.md"} <= included
    assert {"templates/HunterQA-wireless-review-template.json", "templates/08-wireless-review.md"} <= included
    assert {"templates/HunterQA-cloud-review-template.json", "templates/09-cloud-review.md"} <= included
    assert {"templates/HunterQA-mobile-review-template.json", "templates/10-mobile-review.md"} <= included
    assert {"templates/HunterQA-iot-review-template.json", "templates/11-iot-embedded-review.md"} <= included
    assert {"templates/HunterQA-infrastructure-review-template.json", "templates/12-infrastructure-review.md"} <= included
    assert {"templates/HunterQA-exploit-dev-review-template.json", "templates/13-exploit-development-review.md"} <= included
    assert "templates/client-filled-profile.json" not in included
    assert "templates/client-case/findings.json" not in included
    with zipfile.ZipFile(archive_path) as archive:
        assert all(b"PRIVATE_FIXTURE" not in archive.read(name) for name in archive.namelist())


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
        ("action.yml", "name: Source review\n"),
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
        assert "HunterQA-AI/action.yml" in names
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
