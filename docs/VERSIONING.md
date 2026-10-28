# HunterQA AI — Versioning and Release Policy

HunterQA AI follows **Semantic Versioning**: MAJOR.MINOR.PATCH.

- **MAJOR**: breaking changes to CLI commands, report formats or user workflows.
- **MINOR**: new compatible research capabilities and dashboard features.
- **PATCH**: compatible bug fixes and security maintenance.
- **Prerelease**: a preview uses a tag such as `v1.3.0-rc.1` and a Python
  package version such as `1.3.0rc1`. It is never marked latest stable.

## Established historical versions

| Tag | Version | Capability |
| --- | --- | --- |
| `v1.0.0` | 1.0.0 | Stable local research platform |
| `v1.0.1` | 1.0.1 | Kali research lab and release verification |
| `v1.1.0` | 1.1.0 | Explicitly authorized Bug Bounty Edition |
| `v1.2.0` | 1.2.0 | AI Agent Lab, owned local Playwright lab, offline OpenAPI review, evidence correlation, human finding verification and synthetic review benchmarking |

Git tags and published release assets are **immutable**. Never rewrite,
delete or reuse historical tags, force-push `main`, or overwrite versioned
source archives. Historical tagged releases remain downloadable.

## Canonical version

`pyproject.toml` is the source of truth. Its project version is read
directly by the source release builder for RELEASE_MANIFEST.json and
reported from installed package metadata by `hunterqa --version`.
The corresponding public GitHub tag is `vMAJOR.MINOR.PATCH`.

## Release checklist

1. Develop in a separate feature branch, maintain a reviewable PR.
2. Keep private HAR, credentials, engagement scope profiles, passwords,
   raw vulnerability data, SQLite databases and analyst evidence out of Git.
3. Run the full Python regression and offline synthetic research workflow:
   `bash tools/verify_agent_1_2.sh`.
4. For a v1.2 stable release, run the optional *real Chromium* tests against
   the owned temporary 127.0.0.1 server:
   `HUNTERQA_REAL_BROWSER_CI=1 python -m pytest -q tests/test_browser_lab_playwright_v12.py`.
   Browser interception is not an OS network firewall.
5. Verify stable package version, the immutable release manifest, source
   archive members and their per-file SHA-256 digests.
6. Review the version-specific notes, documentation, unchanged historic tags,
   permissions and explicit limitations.
7. Require a green GitHub Actions run on the exact feature-branch head.
8. Merge the PR with explicit owner approval into `main`.
9. Run the version-specific publish workflow on the exact resulting merged
   `main` commit. It repeats all offline and Chromium acceptance before tagging.
10. Verify the resulting GitHub release has the expected immutable tag,
    ZIP asset, SHA-256 checksum, correct version label and successful CI.
    Re-run Kali and dashboard acceptance when updating the local clone.

## Security and evidence

Stable means the **documented local capabilities passed automated release
checks**. It does NOT mean vulnerability exploitability is proven, no false
positives exist, no zero-days can be missed, CVEs can be assigned, third-party
targets may be scanned, or deployment as a public multi-user service is safe.

The Chromium browser lab is restricted to an owned 127.0.0.1 application.
Outbound bounty observations require exact allowlists, explicit consent and
conservative request budgets. The synthetic benchmark evaluates review
suggestions, **not real security-vulnerability detection accuracy**.
Only approved analysts may create attestations and private disclosure drafts.

## Next proposed versions

- `v1.2.1`: maintenance and compatible v1.2 fixes.
- `v1.3.0`: next compatible capability release.
- `v1.3.0-rc.1`: optional pre-release candidate, not stable.
- `v2.0.0`: future incompatible major version.

Refer to docs/RELEASE_1_2_0.md for the explicit release capability inventory.
