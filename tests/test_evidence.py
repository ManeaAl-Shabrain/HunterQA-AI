from hunterqa.evidence import correlate_evidence, evidence_sha256, valid_sha256


def test_unrelated_evidence():
    rows = correlate_evidence([{"sha256": "a" * 64}], [{"input_sha256": "b" * 64}])
    assert rows[0]["correlation_status"] == "not_established"
    assert rows[0]["matched_diagnostics"] == []
    assert rows[0]["zero_day_confirmed"] is False


def test_same_input_not_sufficient_without_build_provenance():
    rows = correlate_evidence([{"sha256": "a" * 64}], [{"input_sha256": "a" * 64}])
    assert rows[0]["correlation_status"] == "same_input_unverified_build"
    assert rows[0]["matched_diagnostics"] == []
    assert rows[0]["candidate_diagnostics_count"] == 1


def test_both_hashes_match_but_still_unverified():
    rows = correlate_evidence([{"sha256": "a" * 64, "binary_sha256": "b" * 64}],
                              [{"input_sha256": "a" * 64, "binary_sha256": "b" * 64}])
    assert rows[0]["correlation_status"] == "matched_input_and_binary"
    assert len(rows[0]["matched_diagnostics"]) == 1
    assert rows[0]["zero_day_confirmed"] is False


def test_same_input_different_build_not_linked():
    rows = correlate_evidence([{"sha256": "a" * 64, "binary_sha256": "b" * 64}],
                              [{"input_sha256": "a" * 64, "binary_sha256": "c" * 64}])
    assert rows[0]["matched_diagnostics"] == []
    assert rows[0]["correlation_status"] == "same_input_unverified_build"


def test_invalid_digest_cannot_match():
    assert not valid_sha256("not-a-hash")
    assert not valid_sha256(123)
    assert evidence_sha256(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert correlate_evidence([{"sha256": "broken"}], [{"input_sha256": "broken"}])[0]["matched_diagnostics"] == []


def test_empty_inputs():
    assert correlate_evidence([], []) == []
