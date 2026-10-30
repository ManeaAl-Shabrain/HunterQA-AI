"""Repository documentation checks for current release source.

These checks use local files only and are safe in PR CI. A README edit must
not accidentally describe a nonexistent path or a stale archive version.
"""
from pathlib import Path
import re
import tomllib
from urllib.parse import unquote

import argparse
import pytest

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
REFERENCE = (ROOT / "docs/COMMAND_REFERENCE.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("filename", ["README.md", "zero to start.md", "docs/COMMAND_REFERENCE.md", "docs/VERSIONING.md",
                                      "docs/SCOPED_RENDERED_DISCOVERY.md", "docs/EXPANSION_PROGRESS.md"])
def test_readme_local_links_resolve_in_repository(filename):
    document = ROOT / filename
    content = document.read_text(encoding="utf-8")
    assert sum(line.startswith("```") for line in content.splitlines()) % 2 == 0
    matches = re.findall(r"\]\(([^)]+)\)", content)
    assert matches, "README lacks navigation links"
    for link in matches:
        if link.startswith(("http://", "https://", "#", "mailto:")):
            continue
        target = unquote(link.strip("<>").rstrip("/")).split("#")[0]
        assert (document.parent / target).exists(), f"Broken local link in {filename}: {link}"


def test_readme_describes_stable_package_and_compatible_archive_commands():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert version == "1.3.0"
    assert f"v{version}" in README
    assert "docs/VERSIONING.md" in README
    versioning = (ROOT / "docs/VERSIONING.md").read_text(encoding="utf-8")
    assert f"HunterQA-AI-{version}-source.zip" in versioning
    assert "python tools/build_release.py" in versioning
    assert "python tools/verify_release_archive.py" in versioning
    assert "immutable" in versioning.casefold()


def test_readme_links_complete_command_reference(monkeypatch):
    from hunterqa.cli import main

    captured = []

    class ParserCaptured(Exception):
        pass

    def capture(parser, *args, **kwargs):
        captured.append(parser)
        raise ParserCaptured

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", capture)
    with pytest.raises(ParserCaptured):
        main([])
    sub = next(action for action in captured[0]._actions if isinstance(action, argparse._SubParsersAction))
    names = set(sub.choices)
    assert len(names) >= 25
    documented = set(re.findall(r"^\| `([^`]+)` \|", REFERENCE, re.MULTILINE))
    assert documented == names
    assert "docs/COMMAND_REFERENCE.md" in README
    assert "hunterqa --version" in README


def test_readme_explicitly_separates_offline_vs_authorized_network_testing():
    for text in ("127.0.0.1", "HUNTERQA_APPROVED_ROOTS", "--authorized", "written permission"):
        assert text.casefold() in README.casefold(), f"Missing safety statement: {text}"
    for text in (
        "bounty-preflight", "bounty-assess", "bounty-replay-head",
        "No guaranteed zero-days", "synthetic",
        "no automatic", "Playwright interception",
    ):
        assert text.casefold() in REFERENCE.casefold(), f"Missing execution boundary: {text}"


def test_release_notes_and_architecture_retain_honest_limits():
    paths = ("docs/ARCHITECTURE.md", "docs/LIMITATIONS.md",
             "SECURITY.md", "docs/RELEASE_1_2_0.md")
    for path in paths:
        content = (ROOT / path).read_text(encoding="utf-8")
        assert "127.0.0.1" in content, path
        assert any(k in content.lower() for k in ("not", "no guarantee", "does not")), path


def test_historical_release_notes_retained():
    for tag in ("1_0_1", "1_1_0", "1_2_0"):
        assert (ROOT / "docs" / f"RELEASE_{tag}.md").is_file()
    assert (ROOT / ".github/workflows/publish-v1.2.0.yml").is_file()
