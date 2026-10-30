"""Release documentation and publication boundary checks; never publishes."""
import re
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("filename", ["README.md", "zero to start.md", "docs/RELEASE_1_3_0.md"])
def test_release_document_links_resolve(filename):
    document = ROOT / filename
    for target in re.findall(r"\]\(([^)]+)\)", document.read_text(encoding="utf-8")):
        target = unquote(target.strip("<>"))
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        assert (document.parent / target.split("#")[0]).is_file(), target


def test_publisher_is_manual_exact_sha_main_only_and_immutable():
    yaml = pytest.importorskip("yaml", reason="YAML syntax validation uses the quality/Bandit dependency")
    path = ROOT / ".github/workflows/publish-v1.3.0.yml"
    workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["on"]["workflow_dispatch"]["inputs"]["expected_sha"]["required"] == "true"
    job = workflow["jobs"]["publish"]
    assert "github.ref == 'refs/heads/main'" in job["if"]
    assert workflow["permissions"]["contents"] == "read"
    assert job["permissions"]["contents"] == "write"
    steps = job["steps"]
    source_guard = next(step["run"] for step in steps if step.get("name", "").startswith("Verify exact"))
    assert "expected == os.environ['GITHUB_SHA']" in source_guard
    publication = steps[-1]["run"]
    assert "--verify-tag" in publication and "gh api --method POST" in publication
    assert "--clobber" not in publication and "--force" not in publication
    assert any("python tools/verify_release_1_3.py" in step.get("run", "") for step in steps)


def test_release_artwork_is_packagable_and_has_accessible_labels():
    image = ROOT / "docs/assets/hunterqa-cybersecurity-infographic.png"
    assert image.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert image.stat().st_size <= 2_000_000
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    labels = re.findall(r"!\[([^\]]+)\]\(docs/assets/hunterqa-cybersecurity-infographic.png\)", readme)
    assert labels and all(len(label.split()) >= 4 for label in labels)
