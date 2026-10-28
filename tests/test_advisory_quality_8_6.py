from datetime import datetime, timezone, timedelta
from hunterqa.engines.advisory_quality import audit_snapshot
from hunterqa.engines.cve_intel import match_snapshot


def test_metadata_age():
    now = datetime(2026, 10, 28, tzinfo=timezone.utc)
    _, meta = audit_snapshot({"snapshot_metadata":{"fetched_at":"2026-10-25T00:00:00Z"},
                             "vulns":[]},now=now)
    assert meta["freshness"] == "within_declared_window"
    _, stale = audit_snapshot({"snapshot_metadata":{"fetched_at":"2026-01-01T00:00:00Z"},
                             "vulns":[]},now=now)
    assert stale["freshness"] == "stale"
    _, unknown = audit_snapshot({"vulns":[]},now=now)
    assert unknown["freshness"] == "unknown"


def test_identical_duplicate_deduped():
    rec = {"id":"GHSA-example","affected":[]}
    items, report = audit_snapshot({"vulns":[rec,dict(rec)]})
    assert len(items) == 1
    assert report["duplicate_ids"] == 1


def test_conflicting_unversioned_duplicate_excluded():
    a = {"id":"GHSA-example","summary":"a","affected":[]}
    b = {"id":"GHSA-example","summary":"b","affected":[]}
    items, report = audit_snapshot({"vulns":[a,b]})
    assert items == []
    assert report["ambiguous_ids_excluded"] == 1


def test_newer_withdrawal_suppresses_older_active_duplicate_in_both_orders():
    active = {"id": "GHSA-withdrawn", "modified": "2026-01-01T00:00:00Z", "affected": []}
    withdrawn = {**active, "modified": "2026-02-01T00:00:00Z", "withdrawn": "2026-02-01T00:00:00Z"}
    for records in ([active, withdrawn], [withdrawn, active]):
        accepted, metadata = audit_snapshot({"vulns": records})
        assert accepted == []
        assert metadata["withdrawn_records"] == 1


def test_undated_conflicting_withdrawal_cannot_resurrect_active_record():
    active = {"id": "GHSA-ambiguous", "affected": []}
    accepted, metadata = audit_snapshot({"vulns": [active, {**active, "withdrawn": "2026-01-01T00:00:00Z"}]})
    assert accepted == []
    assert metadata["ambiguous_ids_excluded"] == 1


def test_scoped_npm_and_packagist_supported():
    dependencies = [
        {"ecosystem":"npm","name":"@scope/demo","version":"1.2.3",
         "resolution":"lockfile_resolved"},
        {"ecosystem":"Packagist","name":"vendor/demo","version":"2.1.0",
         "resolution":"lockfile_resolved"},
    ]
    vulns = [
        {"id":"GHSA-npm","affected":[{"package":{"ecosystem":"npm","name":"@scope/demo"},
         "versions":["1.2.3"]}]},
        {"id":"GHSA-php","affected":[{"package":{"ecosystem":"Packagist","name":"vendor/demo"},
         "versions":["2.1.0"]}]},
    ]
    report = match_snapshot(dependencies,vulns)
    assert len(report["matches"]) == 2
    assert all(not item["confirmed_vulnerability"] for item in report["matches"])
