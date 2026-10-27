
from hunterqa.engines import ai_research


def test_repository_wide_batch_analysis(
    tmp_path, monkeypatch
):
    for number in range(7):
        (tmp_path / f"module_{number}.py").write_text(
            "value = 1\n"
        )

    calls = []

    def fake_ollama(batch, model):
        calls.append(batch)

        return {
            "hypotheses": [{
                "file": batch[0]["file"],
                "line": 1,
                "evidence_quote": "value = 1",
                "potential_weakness": "Test hypothesis",
                "safe_validation_idea": "Review source",
                "remediation_idea": "Review implementation",
                "uncertainty": "Requires verification",
            }]
        }

    monkeypatch.setattr(
        ai_research, "_ask_ollama", fake_ollama
    )

    report = ai_research.analyze_local(
        tmp_path,
        max_files=30,
        max_chunks=40,
        batch_size=2,
    )

    assert report["source_files_discovered"] == 7
    assert report["source_file_count"] == 7
    assert report["source_chunks_analyzed"] == 7
    assert len(calls) == 4
    assert report["zero_days_confirmed"] == 0
    assert report["errors"] == []


def test_rejects_hallucinated_evidence(
    tmp_path, monkeypatch
):
    (tmp_path / "safe.py").write_text(
        "value = 1\n"
    )

    def fake_ollama(batch, model):
        return {
            "hypotheses": [{
                "file": "safe.py",
                "line": 1,
                "evidence_quote": "dangerous_call()",
                "potential_weakness": "Invented weakness",
            }]
        }

    monkeypatch.setattr(
        ai_research, "_ask_ollama", fake_ollama
    )

    report = ai_research.analyze_local(tmp_path)

    assert report["hypotheses"] == []
    assert report["ungrounded_suggestions_rejected"] == 1


def test_skips_symlinked_and_secret_files(tmp_path):
    outside = tmp_path.parent / "external_hunterqa.py"
    outside.write_text("SECRET = 'do-not-read'\n")

    (tmp_path / "linked.py").symlink_to(outside)
    (tmp_path / ".env").write_text(
        "API_KEY=not-for-analysis"
    )
    (tmp_path / "main.py").write_text(
        "value = 1\n"
    )

    samples = ai_research.source_samples(
        tmp_path, max_files=20
    )

    assert [s["file"] for s in samples] == ["main.py"]
