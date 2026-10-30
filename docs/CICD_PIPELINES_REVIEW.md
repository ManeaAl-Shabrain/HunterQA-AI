# HunterQA — CI/CD & Pipelines review

This pack implements two offline assurance contracts and selected static GitHub
Actions JSON checks. It is partial coverage, not an automated CI/CD penetration
test, compliance verdict or guarantee of secret protection.

| Skill | Implemented | Requires independent evidence |
| --- | --- | --- |
| `offensive-cicd-pipeline` | Trust/permissions/pinning/runner/approval observations; selected Actions JSON cues | Actual trust boundaries, runner isolation, approvals and exploitability |
| `offensive-cicd-secrets` | Scope/redaction/OIDC/artifact/rotation observations; inherited-secret cue | Effective secret access, log redaction and federation restrictions |

## Start with private evidence

1. Obtain owner approval covering the repository, workflow files and local review.
2. Create a private directory outside this repository. Copy
   [the template](../templates/HunterQA-cicd-review-template.json) and
   [worksheet](../templates/18-cicd-pipelines-review.md) there.
3. Set `HUNTERQA_APPROVED_ROOTS` to its absolute directory path. It covers both
   input and output parents. Never use your entire disk or commit filled evidence.
4. Fill observations with `true` only when independently supported, `false` for
   an identified assurance gap, or `null` for unknown. An attestation does not
   independently verify owner consent or runtime enforcement.
5. Run the commands below using absolute private paths. Choose a fresh output
   filename each time; existing files are never overwritten.

```text
hunterqa cicd-review-catalog
hunterqa cicd-review --input /absolute/private/observations.json --out /absolute/private/observations-report.json --authorized
hunterqa cicd-workflow-review --input /absolute/private/workflow.json --out /absolute/private/workflow-report.json --authorized
```

On PowerShell, set `$env:HUNTERQA_APPROVED_ROOTS = 'C:\Private\HunterQA'` and use
Windows absolute paths. On Linux, use `export HUNTERQA_APPROVED_ROOTS=/absolute/private`.
No tool, action, workflow, script, include or remote reference is executed.

## Saved GitHub Actions JSON mode

Input is a single workflow object, not an API workflow metadata response or a
list. **YAML is not accepted.** If using an independently reviewed offline
converter, preserve string keys (especially `on`), reject duplicate YAML keys and
verify conversion fidelity privately. HunterQA does not perform this conversion.
The receipt hashes the supplied JSON bytes, not the original YAML or provenance.

Minimal synthetic declaration:

```json
{
  "on": "workflow_dispatch",
  "permissions": {},
  "jobs": {
    "owned-example": {
      "runs-on": "ubuntu-latest",
      "steps": [{"run": "echo owned-example"}]
    }
  }
}
```

Selected cues cover workflow/job `permissions`, remote action/reusable workflow
SHA forms, Docker action digest forms, `pull_request_target`, `secrets: inherit`
and direct script interpolation of selected event contexts. Job permissions
replace workflow permissions; the workflow declaration is also separately
reported for review. Missing permissions remain externally defaulted/unknown.
Local action contents and pinned references are not inspected or trusted.

Conditions, matrices, expression values, event filtering, branch/environment
protection, organization policy and OIDC claims are not evaluated. Static cues can
be intentional or unreachable. Unrecognized injection syntax and indirect secret
flows can be missed. Jenkins, GitLab and Azure DevOps are covered only by manually
supported observations, with no native parser. No build-log secret scan, vault
access, token extraction, artifact download or live validation is performed.

## Evidence and limits

Reports contain SHA-256 receipts and numbered source-derived case IDs. Names,
commands, action references, inputs, environment variables and values are not
exported. Keep even sanitized reports private. Findings are `INFO`, unverified
review candidates with remediation guidance, not confirmed vulnerabilities.
No findings means no selected cue was found; it does not mean the pipeline is safe.

Inputs must be authorized, approved-root regular files, at most 1 MiB. Duplicate
JSON keys, nonfinite numbers, excessive depth/nodes and malformed selected fields
are rejected with sanitized errors. Bounds: 100 jobs, 200 steps/job, 1,000 total
steps, 500 retained findings with explicit truncation accounting. Normalized
contracts allow at most 10 records per skill and 20 total. Unknown fields within
native workflow objects are not evaluated; this is not complete schema validation.

Owned synthetic regression tests cover positive/negative/unknown declarations,
permission precedence, sanitized output, authorization, file limits and absence
of process/network execution. They do not establish real-world effectiveness.

## References and next category

- [Upstream category index](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/cicd)
- [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)

**Next requested category: Cryptography.** It is not delivered by this pack.
