"""Repository documentation checks for current v1.2.0 source.

These checks use local files only and are safe in PR CI. A README edit must
not accidentally describe a nonexistent path or a stale archive version.
"""
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_local_links_resolve_in_repository():
    matches = re.findall(r"\]\(([^)]+)\)", README)
    assert matches, "README lacks navigation links"
    for link in matches:
        if link.startswith(("http://", "https://", "#", "mailto:")):
            continue
        assert (ROOT / link.rstrip("/")).exists(), f"Broken local README link: {link}"


def test_readme_describes_stable_package_and_compatible_archive_commands():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert version == "1.2.0"
    assert f"v{version}" in README
    assert f"HunterQA-AI-{version}-source.zip" in README
    assert "HunterQA-AI-1.1.0-source.zip" not in README
    assert "python tools/build_release.py" in README
    assert "python tools/verify_release_archive.py" in README
    assert "docs/VERSIONING.md" in README


def test_readme_documents_cli_groups_and_all_commands():
    cli = (ROOT / "hunterqa" / "cli.py").read_text(encoding="utf-8")
    names = set(re.findall(r'sub\.add_parser\("([^"]+)"', cli))
    assert len(names) >= 25
    for name in names:
        assert name in README, f"Undocumented CLI subcommand: {name}"
    assert "hunterqa --version" in README


def test_readme_explicitly_separates_offline_vs_authorized_network_testing():
    for text in (
        "127.0.0.1", "HUNTERQA_APPROVED_ROOTS", "--authorized",
        "bounty-preflight", "bounty-assess", "bounty-replay-head",
        "No guaranteed zero-days", "synthetic",
        "no automatic", "Playwright interception",
    ):
        assert text.casefold() in README.casefold(), f"Missing safety statement: {text}"


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
