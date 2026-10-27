from hunterqa.engines.cve_intel import match_snapshot
from hunterqa.engines.cve_ranges import range_affected

PACKAGE = [{"ecosystem": "PyPI", "name": "jinja2",
            "version": "3.1.3", "source": "requirements.txt"}]


def test_ghsa_pysec_aliases_group_but_keep_sources():
    advisories = [
        {"id": "GHSA-example", "aliases": ["CVE-2024-12345"],
         "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"},
                       "versions": ["3.1.3"]}]},
        {"id": "PYSEC-example", "aliases": ["CVE-2024-12345"],
         "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"},
                       "versions": ["3.1.3"]}]},
    ]
    result = match_snapshot(PACKAGE, advisories)
    assert len(result["matches"]) == 2
    assert len(result["cve_groups"]) == 1
    assert result["cve_groups"][0]["advisory_ids"] == ["GHSA-example", "PYSEC-example"]
    assert result["cve_groups"][0]["confirmed_vulnerability"] is False


def test_pypi_range_open_and_fixed():
    affected = {"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "3.1.4"}]}
    assert range_affected("3.1.3", "PyPI", affected) == "affected"
    assert range_affected("3.1.4", "PyPI", affected) == "not_listed"


def test_pypi_last_affected_inclusive():
    affected = {"type": "ECOSYSTEM", "events": [
        {"introduced": "1.0"}, {"last_affected": "2.0"}]}
    assert range_affected("2.0", "PyPI", affected) == "affected"
    assert range_affected("2.0.1", "PyPI", affected) == "not_listed"


def test_unsupported_range_never_guesses():
    affected = {"type": "GIT", "events": [{"introduced": "deadbeef"}]}
    assert range_affected("3.1.3", "PyPI", affected) == "unknown"


def test_semver_prerelease():
    affected = {"type": "SEMVER", "events": [
        {"introduced": "1.0.0-alpha"}, {"fixed": "1.0.0"}]}
    assert range_affected("1.0.0-beta", "npm", affected) == "affected"
    assert range_affected("1.0.0", "npm", affected) == "not_listed"


def test_range_match_not_confirmed():
    advisory = {"id": "OSV-range", "aliases": ["CVE-2025-12345"],
                "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [
                                  {"introduced": "0"}, {"fixed": "3.1.4"}]}]}]}
    result = match_snapshot(PACKAGE, [advisory])
    assert result["matches"][0]["evidence_method"] == "OSV ECOSYSTEM interval"
    assert result["matches"][0]["confirmed_vulnerability"] is False


def test_invalid_events_fail_closed():
    affected = {"type": "ECOSYSTEM", "events": [
        {"fixed": "2.0"}, {"introduced": "1.0"}]}
    assert range_affected("1.3", "PyPI", affected) == "unknown"
