# HunterQA AI v1.2 — Analyst Verification and Disclosure Workflow

**Status:** development milestone in draft PR #19. The public `v1.1.0`
release remains unchanged. This tool operates entirely offline and saves
its outputs only in approved private local directories.

## Research evidence pipeline

```text
Approved program scope + local HTTP/HAR / OpenAPI evidence
  -> bounty-correlate (unknown candidates remain unconfirmed)
  -> bounty-review-init (private, unverified finding dossier)
  -> bounty-reproduction-note (separate explicit human attestation)
  -> bounty-review-decide (new hash-linked dossier version)
  -> bounty-review-export (private disclosure draft for validated cases only)
```

### Requirements

- Set `HUNTERQA_APPROVED_ROOTS` to private, operator-approved Kali folders.
- Keep raw HAR, private reproduction artifacts, tokens, passwords and account
  information out of the public Git repository.
- Use only explicitly authorized test assets and accounts.
- A consistent program profile is required for every stage. Changing even
  one byte in the profile changes its SHA-256 identity and invalidates any
  existing reviewed evidence until a new, authorized dossier is prepared.
- No command in this workflow performs live HTTP, browser interaction,
  exploitation, or automatic HackerOne/Bugcrowd submission.

## Quick local workflow

The commands below assume you already generated
`profile.json` and `correlation.json` following
`docs/V1_2_DEV.md`. Choose new output filenames for every run.

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"

folder="$HOME/ZeroScope-AI/research-lab/v12"

python -m hunterqa bounty-review-init \
  --profile "$folder/profile.json" \
  --correlation "$folder/correlation.json" \
  --out "$folder/review-dossier-001.json" --authorized
```

To list available finding IDs without exposing raw captures:

```bash
python - "$folder/review-dossier-001.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    dossier = json.load(handle)
for item in dossier["cases"]:
    print(item["id"], item["rule_id"], item["status"])
PY
```

A finding that is not reproducible can be labeled without claiming impact:

```bash
python -m hunterqa bounty-review-decide \
  --profile "$folder/profile.json" \
  --dossier "$folder/review-dossier-001.json" \
  --case REPLACE_WITH_EXACT_20_HEX_CASE_ID \
  --decision not_reproducible --reviewer local_analyst \
  --out "$folder/review-dossier-002.json" --authorized
```

To mark an observation `analyst_validated`, first independently reproduce it
on the authorized target without collecting unrelated user data. Record a
private manual attestation of what was expected and what actually occurred.

```bash
python -m hunterqa bounty-reproduction-note \
  --profile "$folder/profile.json" \
  --case REPLACE_WITH_EXACT_20_HEX_CASE_ID \
  --reviewer local_analyst --context approved_test_accounts \
  --expected "Authorized test identity A should see only its own lab resource." \
  --observed "In the owned fixture, identity A observed the controlled identity B resource." \
  --out "$folder/reproduction-001.json" \
  --authorized --attest

python -m hunterqa bounty-review-decide \
  --profile "$folder/profile.json" \
  --dossier "$folder/review-dossier-001.json" \
  --case REPLACE_WITH_EXACT_20_HEX_CASE_ID \
  --decision analyst_validated --reviewer local_analyst \
  --impact "A manually verified issue affects the permitted test account's authorization boundary." \
  --reproduction "Using only permitted test identities, repeat the request and compare ownership responses." \
  --evidence "$folder/reproduction-001.json" \
  --out "$folder/review-dossier-validated-002.json" --authorized
```

The note has a schema, policy digest, finding ID, reviewer alias,
`human_reproduced_attestation: true`, and a declaration that unrelated
third-party data was not exported. HunterQA checks the note before accepting
the `analyst_validated` decision. These are **human-supplied statements**;
a forged note is still possible and not independently verified by the tool.

Create a report only from your final reviewed dossier:

```bash
python -m hunterqa bounty-review-export \
  --profile "$folder/profile.json" \
  --dossier "$folder/review-dossier-validated-002.json" \
  --out "$folder/private-disclosure-draft.md" --authorized
```

The draft includes the relevant known finding category, reproduction note
hash, analyst-supplied impact and reproduction text, and disclosure caveats.
You must manually provide the specific in-scope asset and review the
platform's program rules, proof of impact, duplicates and sensitive content.

## HEAD replay repeatability (offline)

After generating two separate `bounty-replay-head` reports from the same
sanitized HAR baseline with an identical approved scope profile:

```bash
python -m hunterqa bounty-repeatability \
  --profile "$folder/profile.json" \
  --first "$folder/head-001.json" \
  --second "$folder/head-002.json" \
  --out "$folder/head-repeatability-001.json" --authorized
```

Only matching target fingerprints from the same HAR and policy are compared.
The output counts stable versus different HTTP response statuses. It
**does not reproduce a security flaw**, and no network requests are made
by the comparison.

## Dashboard and privacy

```bash
export HUNTERQA_REVIEW_DOSSIER="$folder/review-dossier-validated-002.json"
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
python run.py
```

The read-only `http://127.0.0.1:5000/agent-lab` dashboard displays only
case totals and review-status counts. Analyst notes, target URLs, reproduced
payloads, tokens and evidence content are never displayed by the new cards.

## Audit and safety limits

- Each decision creates a new SHA-256-linked event and must be written to a
  **new file** with restrictive file permissions. Existing dossiers are not
  overwritten by the CLI.
- A SHA-256 chain detects accidental edits and many inconsistencies. It is
  not digitally signed and does not prevent a malicious person with file
  access from rebuilding an entire falsified chain.
- Human analyst validation is not proof of third-party impact, an exploit, a
  zero-day, or an official CVE.
- Repeated status codes, missing headers, AI hypotheses, and database
  version matches never become automatically confirmed vulnerabilities.
- Reporting remains local-only; there is no automated submission or leak of
  private engagement data to HackerOne/Bugcrowd.
