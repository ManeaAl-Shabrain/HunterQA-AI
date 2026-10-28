"""Stable version consistency and release archive integrity regression tests."""
from __future__ import annotations

import json
import tomllib
from importlib.metadata import version as installed_version
from pathlib import Path
from zipfile import ZipFile

import pytest

from hunterqa.cli import main
from tools.build_release import build
from tools.verify_release_archive import verify_archive


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_STABLE = "1.3.0"


def test_version_from_project_metadata_and_installed_cli(capsys):
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["name"] == "hunterqa-ai"
    assert meta["project"]["version"] == EXPECTED_STABLE
    assert installed_version("hunterqa-ai") == EXPECTED_STABLE
    with pytest.raises(SystemExit) as out:
        main(["--version"])
    assert out.value.code == 0
    assert capsys.readouterr().out.strip() == "HunterQA AI " + EXPECTED_STABLE


def test_stable_archive_uses_canonical_version_and_preserves_source_integrity(tmp_path):
    archive = tmp_path / f"HunterQA-AI-{EXPECTED_STABLE}-source.zip"
    manifest = build(ROOT, archive)
    assert manifest["project"] == "HunterQA AI"
    assert manifest["release"] == EXPECTED_STABLE
    count = verify_archive(archive)
    assert count == len(manifest["files"]) >= 190
    with ZipFile(archive) as reader:
        embedded = json.loads(reader.read("HunterQA-AI/RELEASE_MANIFEST.json"))
        assert embedded == manifest
        assert f'version = "{EXPECTED_STABLE}"'.encode() in reader.read("HunterQA-AI/pyproject.toml")
        required = {
            "HunterQA-AI/docs/RELEASE_1_3_0.md",
            "HunterQA-AI/docs/WORKFLOW_RUNNER.md",
            "HunterQA-AI/docs/assets/hunterqa-cybersecurity-infographic.png",
            "HunterQA-AI/zero to start.md",
            "HunterQA-AI/tools/verify_release_1_3.py",
            "HunterQA-AI/docs/VERSIONING.md",
            "HunterQA-AI/docs/RELEASE_1_2_0.md",
            "HunterQA-AI/docs/REVIEW_V1_2.md",
            "HunterQA-AI/docs/BENCHMARK_V1_2.md",
            "HunterQA-AI/docs/BROWSER_LAB_V1_2.md",
            "HunterQA-AI/hunterqa/browser_lab_v12.py",
            "HunterQA-AI/hunterqa/replay_v12.py",
            "HunterQA-AI/hunterqa/verification_v12.py",
            "HunterQA-AI/hunterqa/benchmark_v12.py",
            "HunterQA-AI/hunterqa/templates/agent_lab.html",
            "HunterQA-AI/LICENSE",
        }
        assert required.issubset(set(reader.namelist()))


def test_version_notes_and_tag_policy_do_not_claim_unrestricted_exploitation():
    versioning = (ROOT / "docs/VERSIONING.md").read_text(encoding="utf-8")
    release = (ROOT / "docs/RELEASE_1_2_0.md").read_text(encoding="utf-8")
    assert "v1.2.0" in versioning and "v1.1.0" in versioning
    assert "v1.2.1" in versioning and "v1.3.0" in versioning
    assert "v1.2.0" in release and "HunterQA-AI-1.2.0-source.zip.sha256" in release
    assert "not" in release.lower()
    assert "127.0.0.1" in release
