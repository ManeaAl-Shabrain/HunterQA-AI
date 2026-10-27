import json
from hunterqa.engines.dependencies import inventory
from hunterqa.engines.cve_intel import match_snapshot


def test_npm_resolved_and_constraints_separate(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies":{"example":"^1.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"version": "1.0.0"}, "node_modules/example": {"version": "1.2.0"}}
    }))
    rows = inventory(tmp_path)
    assert any(x["ecosystem"] == "npm" and x["version"] == "1.2.0"
               and x["resolution"] == "lockfile_resolved" for x in rows)
    advisory = [{"id": "GHSA-demo", "aliases": ["CVE-2025-10001"],
        "affected": [{"package": {"ecosystem": "npm", "name": "example"},
                      "ranges": [{"type": "SEMVER", "events": [
                          {"introduced": "1.0.0"}, {"fixed": "1.3.0"}]}]}]}]
    matched = match_snapshot(rows, advisory)
    assert len(matched["matches"]) == 1
    assert matched["matches"][0]["declared_version"] == "1.2.0"


def test_composer_lock_explicit_versions(tmp_path):
    (tmp_path / "composer.lock").write_text(json.dumps({
        "packages": [{"name": "vendor/package", "version": "1.2.3"}],
        "packages-dev": [{"name": "vendor/dev", "version": "2.0.0"}]
    }))
    rows = inventory(tmp_path)
    assert len(rows) == 2
    assert all(r["ecosystem"] == "Packagist" and r["resolution"] == "lockfile_resolved" for r in rows)
    assert {r["scope"] for r in rows} == {"production", "dev"}


def test_poetry_and_uv_lock(tmp_path):
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "jinja2"\nversion = "3.1.3"\n')
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "flask"\nversion = "3.1.3"\nsource = { registry = "https://pypi.org/simple" }\n')
    rows = inventory(tmp_path)
    assert {(r["name"], r["version"]) for r in rows} == {
        ("jinja2", "3.1.3"), ("flask", "3.1.3")
    }


def test_uv_non_registry_source_not_misclassified(tmp_path):
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "local-source"\nversion = "1.2.3"\nsource = { editable = "." }\n')
    assert inventory(tmp_path) == []


def test_npm_links_and_unresolved_manifest_not_matched(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"demo": "^2.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/demo": {"link": True, "version": "2.0.0"}}
    }))
    rows = inventory(tmp_path)
    advisory = [{"id":"OSV-demo", "affected":[{"package":{"ecosystem":"npm","name":"demo"},
              "versions":["2.0.0"]}]}]
    assert match_snapshot(rows, advisory)["matches"] == []


def test_invalid_lockfile_bounded(tmp_path):
    (tmp_path / "composer.lock").write_text("{bad")
    (tmp_path / "uv.lock").write_text("x" * 4_000_001)
    assert inventory(tmp_path) == []
