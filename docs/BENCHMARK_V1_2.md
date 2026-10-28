# HunterQA AI 1.2 — Offline Review-Cue Benchmark

**Status:** v1.2 development on draft PR #19. v1.1.0 Stable is unchanged.

## Why this benchmark exists

HunterQA already researches local source, OpenAPI specifications, fuzzing,
sanitizer evidence and authorized HTTP observations. More alerts do not always
mean better security results. This milestone gives its OpenAPI reviewer
a labeled, repeatable regression test for useful review suggestions, missed
suggestions and unnecessary review suggestions.

**Important:** These precision/recall scores measure SYNTHETIC REVIEW CUES,
not security vulnerabilities. A missing OpenAPI authorization declaration
is not proof of missing runtime authorization, exploitability, a CVE or a
zero-day. Perfect results here do not predict real bug bounty success.

## What is included

All content is synthetic and offline:

- examples/benchmarks/v12_scoped_auth.json: test routes with documented
  security declarations, object identifiers, sensitive operations and a
  deliberately public operation
- examples/benchmarks/v12_missing_auth.json: test routes with missing
  declaration metadata, an intentionally public operation and a deprecated
  operation
- examples/benchmarks/v12_openapi_golden.json: independent manually curated
  labels for expected and unexpected METHOD / PATH / RULE combinations

The pack has 10 positive review-cue expectations and 21 negative checks.
Unlabeled emitted predictions are also penalized as false positives. The
review scoreboard includes TP, FP, FN, TN, precision, recall, F1 and the
false-positive rate on explicitly negative labels. No real application is
contacted; all failure target identifiers are hashed.

## Kali: one local command

Use a checkout of feature/v1-2-ai-research-orchestration.
Activate the installed virtual environment, then:

    cd ~/Desktop/HunterQA-AI
    source .venv/bin/activate
    mkdir -p "$HOME/ZeroScope-AI/research-lab/v12/benchmarks"
    cp examples/benchmarks/*.json "$HOME/ZeroScope-AI/research-lab/v12/benchmarks/"
    export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"

    python -m hunterqa bounty-benchmark \
      --profile "$HOME/ZeroScope-AI/research-lab/v12/profile.json" \
      --pack "$HOME/ZeroScope-AI/research-lab/v12/benchmarks/v12_openapi_golden.json" \
      --out "$HOME/ZeroScope-AI/research-lab/v12/benchmark-001.json" \
      --authorized --strict

Expected result for the included fixtures:

    true_positive_review_suggestions: 10
    true_negative_review_checks: 21
    false_positive_review_suggestions: 0
    missed_review_suggestions: 0
    Review expectation gate: PASS

The benchmark uses no HTTP, Playwright, Ollama, shell execution of schema
content, or bug bounty scanning. Use a NEW output filename on each run.
The strict option saves a private report and rejects any missed expected
review cues or extra/unexpected cues with a nonzero CLI exit.

The full v1.2 test command also runs this gate:

    bash tools/verify_agent_1_2.sh

## AI Agent Lab

Set the saved, approved benchmark path before launching the local dashboard:

    export HUNTERQA_BENCHMARK_REPORT="$HOME/ZeroScope-AI/research-lab/v12/benchmark-001.json"
    export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
    python run.py

Open http://127.0.0.1:5000/agent-lab.

The Review Cue Calibration card displays only approved, count-based local
metrics and never runs a scan or sends any network requests. It does not
show raw OpenAPI contents, credential material, real target URLs or private
analyst notes.

## Limits and next steps

The curated pack is small; labels represent expected REVIEW prompts only,
not real known vulnerabilities. Expanding to more complex synthetic lab
scenarios needs additional independent labeling, scrutiny of false-positive
categories and review of any third-party example licenses.

Verified findings must still be reproduced in an owned or explicitly
authorized system, and pass the manual analyst workflow described in
docs/REVIEW_V1_2.md. A hash, AI suggestion or repeated HTTP status is
not an independent vulnerability proof. Never describe these synthetic
precision/recall numbers as real-world detection accuracy or zero-day rates.
