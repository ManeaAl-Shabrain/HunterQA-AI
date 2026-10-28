# HunterQA v1.3.0 · Controlled Workflows and Evidence

Prepared release source. Publication is established only by the corresponding
GitHub release/tag and verified assets; this document alone does not publish it.

## Release assets

- Tag: `v1.3.0` on the exact reviewed merged `main` commit.
- Source: `HunterQA-AI-1.3.0-source.zip`.
- Checksum: `HunterQA-AI-1.3.0-source.zip.sha256`.
- Internal per-file manifest: `HunterQA-AI/RELEASE_MANIFEST.json`.

## Included changes since 1.2.0

| Area | Delivered |
| --- | --- |
| Runtime | Fixed-adapter workflow execution, dependency/stage scheduling, durable SQLite state and exclusive coordinator lock |
| Controls | Exact scope binding, execution/runtime fingerprints, explicit checkpoints, request reservations, concurrency/time limits and supervised stop |
| Recovery | Independent worker watchdogs and no-replay abandonment of crashed coordinators |
| Evidence | Durable network-intent/outcome journals, project-aware candidate deduplication, evidence-linked analyst review and conservative retesting |
| Reporting | Automatic JSON, printable HTML and SARIF; read-only mobile-compatible workflow and saved-assessment views |
| Research | Original playbooks, private journals, offline Nuclei/ZAP imports, conservative SARIF export and reusable source-only GitHub Action |
| Engagements | Expiring exact-request plans, bounded observations, benign WAF canary, separate dedicated-account check and narrow remote HTTPS form review |
| Maintenance | Loopback AI/dashboard protections, bounded source/import handling, advisory/OpenAPI fixes and verified portable source packaging |
| Documentation | Rewritten README/Kali guide and original HunterQA cybersecurity infographic |

The seven workflow adapters cover declared assets, imported service evidence,
configuration/OpenAPI/dependency review, external findings import, fixed HEAD/GET
observations, evidence indexing and report inputs. Account/browser workers,
arbitrary external scanner execution and distributed orchestration are absent.
Existing command-specific Semgrep, browser, account and isolated crash workflows
remain available under their original controls.

## Compatibility and migration

- Requires Python 3.11+; primary release QA runs on Linux with Python 3.11/3.13.
- Public package name remains `hunterqa-ai`; CLI remains `hunterqa`.
- Existing profile and protocol schema versions remain unchanged.
- Reinstall the editable package after updating; the canonical version is 1.3.0.
- Recreate/review execution plans after upgrading: runtime-source fingerprints change.
- Back up complete private cases before updates. Interrupted work is never automatically replayed.
- Do not overwrite historical release tags, archives or analyst evidence.

## Validation gate

The release PR must pass regression, static/dependency checks, original fixture
tests, Semgrep rules, source Action, offline acceptance, real Chromium owned-lab
and synthetic checks, and complete source-archive verification. The manual
publisher repeats checks on the exact merged `main` SHA before creating a tag.
Only owned temporary lab services or synthetic responses are tested.

## Documented limits

This is a local single-operator release, not a publicly hosted multi-user service.
The dashboard stays on `127.0.0.1`. Local approval/reviewer references are
attestations, not verified company identities or independent owner grants.
Worker processes are not an OS sandbox; quotas apply per run, not organization.
Linux adds worker resource limits; Windows support is limited to compatible
offline workflows and relies on inherited directory permissions.

Scanner severity and analyst decisions are not automatic exploit proofs. A
request-intent record does not prove delivery. Missing retest findings do not
prove repair. Browser interception is not a firewall. No unrestricted exploit
executor, credential guessing, stealth/WAF bypass, automatic submission, official
CVE allocation or guaranteed zero-day discovery is included.

See [runtime contracts](WORKFLOW_RUNNER.md), [engagement limits](APPROVED_ASSESSMENTS.md)
and [the operator guide](../zero%20to%20start.md) before live use.
