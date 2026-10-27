# Phase 7.5.3: HunterQA analyst review

Local-only review status tracking over existing read-only triage JSON reports.

- `triage_reviews` holds the latest analyst status and note, keyed by the triage record ID and the source evidence hash.
- `triage_review_events` is an append-only log of review transitions and notes; the existing `audit_events` records the update.
- States: new -> in_review -> confirmed / false_positive -> remediated. Reopening a record for investigation is supported.
- `confirmed` is an analyst action with supporting notes. It does **not** confirm exploitability, CVE, CVSS score or zero-day status.
- The original JSON evidence is never modified and its hash must match the stored review. Changed evidence resets the visible status to `new` pending independent review.
- Potential duplicate groups are suggestions based on shared source file and security-operation tokens. The engine intentionally does not merge records, especially across crash/sanitizer evidence.
- Intended for the existing `127.0.0.1`-bound research application. It is not a multi-user authenticated web service.

Every POST requires the application's existing CSRF token. SQLite tables are created idempotently on application startup. Existing report files stay in the research-lab directory.
