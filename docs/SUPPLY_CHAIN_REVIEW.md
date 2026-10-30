# HunterQA — Supply Chain review

Two offline assurance contracts and selected package-metadata/configuration checks
extend the existing dependency inventory. This is partial coverage, not dependency
resolution, artifact verification or a dependency-confusion exploitation test.

| Upstream skill ID | Implemented review coverage | Independent evidence still needed |
| --- | --- | --- |
| `offensive-supply-chain` | Artifact/build/maintainer assurance observations; selected lock integrity shape, install-script and source declarations | Actual artifact bytes, provenance/signatures, publisher trust, build isolation and release controls |
| `offensive-dependency-confusion` | Namespace/source/credential-policy observations; selected npmrc/pip settings and URL user-information cues | Effective precedence/resolution, private namespace ownership, registry trust and selected artifacts |

## Start privately

1. Record owner authorization for local configuration/evidence review, collection
   provenance, reviewer and the approved package-source/integrity baseline.
2. Copy [the JSON template](../templates/HunterQA-supply-chain-review-template.json)
   and [worksheet](../templates/23-supply-chain-review.md) outside this repository.
   Avoid supplying secrets; config files can contain tokens and credential URLs.
3. Set `HUNTERQA_APPROVED_ROOTS` to the narrow absolute private directory covering
   inputs and output parent. Never commit filled templates, private package names,
   source URLs, tokens or reports. Use a fresh output filename; no overwrite.
4. Set observations to `true` for supported assurance review, `false` for a declared
   assurance gap, or `null` for unassessed. Keep private supporting references in
   the worksheet, not additional JSON fields.
5. Select a saved input mode; no dependencies, included files or remote sources
   are opened. Source receipts hash the supplied bytes, not artifact contents.

```text
hunterqa supply-chain-review-catalog
hunterqa supply-chain-review --input /absolute/private/observations.json --out /absolute/private/review.json --authorized
hunterqa supply-chain-config-review --mode npm-lock-json --input /absolute/private/package-lock.json --out /absolute/private/lock-report.json --authorized
hunterqa supply-chain-config-review --mode npmrc-text --input /absolute/private/project.npmrc --out /absolute/private/npmrc-report.json --authorized
hunterqa supply-chain-config-review --mode pip-conf --input /absolute/private/pip.conf --out /absolute/private/pip-report.json --authorized
```

PowerShell: `$env:HUNTERQA_APPROVED_ROOTS = 'C:\Private\HunterQA'`, with Windows
absolute paths. Linux: `export HUNTERQA_APPROVED_ROOTS=/absolute/private`.
No registry/DNS query, install, script execution, namespace registration, malicious
package publication, takeover or callback is performed.

## npm lock v2/v3 JSON

Accepts a `packages` map with integer `lockfileVersion` 2 or 3 (including saved
npm-shrinkwrap in that shape). The empty root metadata entry is counted separately
and not reviewed. Selected fields are `resolved`, `integrity`, `link` and
`hasInstallScript`; other fields are not evaluated. Missing fields stay unknown.

HTTP(S) artifact declarations without a recognized selected strong digest shape
produce a review cue, except link entries. Supported shapes are standard base64
SHA-256/384/512 digest-length forms; SHA-1-only, missing or unrecognized forms
remain review candidates. No digest is compared with artifact bytes, and no
signature, publisher or provenance is verified. Recognized hash syntax is not
proof of authenticity or successful package-manager verification. SRI options,
other algorithms and complete SRI semantics are not supported.

Plain HTTP URLs, embedded URL user information and explicit install-script flags
also yield informational cues. Scripts are not read or executed. Local/git/other
sources and unresolved expressions remain unverified; aliases, workspace links,
root lifecycle scripts and the dependency graph are not resolved. Existing
inventory/advisory matching remains separate from this review.

## Saved npmrc text

Selected literal `key=value` assignments cover `registry`, `@scope:registry`,
`strict-ssl`, `ignore-scripts` and `package-lock`. Full-line `#`/`;` comments and
simple matching quote pairs are supported. Duplicate selected keys fail; unknown
assignments (including token settings) are counted and not inspected/exported.
No inline-comment, array, negated-option, file-layer or full npm INI emulation is
provided. Unsupported selected boolean values fail rather than being inferred.

False selected flags, plain HTTP and URL user-information declarations produce
review cues. Boolean `${...}` and URL interpolation forms remain unresolved.
A scope declaration alone does not establish correct mapping or namespace
ownership. Missing scope mappings/defaults are not automatically vulnerabilities;
no private package/scope inventory is inferred from names.

## Saved pip INI

Reads selected options in exact `[global]`, `[install]`, `[download]`, `[wheel]`
sections: `index-url`, `extra-index-url`, `trusted-host`, `require-hashes`, `no-index`.
Multiline URL lists and standard INI boolean forms are supported. Duplicate
sections/options, malformed input and nonempty `[DEFAULT]` inheritance fail with
content-withholding errors. Unknown sections/options are counted as unreviewed.
Environment interpolation and referenced configurations are never evaluated.

Additional indexes, trusted-host exceptions, disabled hash requirements and selected
URL issues are review cues. `no-index` is retained as context, but merging sections,
CLI/environment/user/global precedence and whether any option actually applies
are not computed. An additional index does not create a private-first trust
boundary. Review the actual source-isolation policy with the owner; no package
name is tested against a public registry and no confusion exploit is established.

## Reports, bounds and validation

Reports withhold package names, scopes, paths, URLs/hosts, credentials, scripts and
digest values. They retain input SHA-256 receipts, numbered source-derived cases,
selected boolean/enum/count declarations and coverage limits. Keep even sanitized
reports private. Findings are `INFO`, unverified candidates with generic review
and remediation guidance. Conservative SARIF export omits source locations.

Inputs require explicit authorization and approved-root regular non-symlink files
of at most 1 MiB. Strict JSON rejects duplicate keys, nonfinite numbers, malformed
selected fields and excessive depth/nodes. Bounds: 10 observations per skill/20
total; 1,500 npm package entries; text 1,000 lines/4,096 characters per line; up to
20 URLs per pip source option; 500 retained findings with explicit truncation counts.
Errors withhold input contents. Approved roots reduce accidental access, not
hostile concurrent filesystem mutation.

No findings does not establish package safety, namespace ownership or correct
resolution. No artifact digest/signature verification, malware/CVE verdict, full
package-manager schema support, SBOM attestation or reproducible-build proof is
provided here. Maven/NuGet/Go/Ruby/container-registry routing use owner assurance
observations only. All seven broad readiness areas remain partial, and real-world
effectiveness remains unverified.

Owned synthetic tests cover matches/non-matches/unknowns, integrity shapes, selected
config declarations, privacy, parser/file limits, authorization, no-overwrite,
SARIF and absence of process/network execution.

## References and next category

- [Upstream category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/supply-chain)
- [npm package-lock metadata](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/)
- [npmrc](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/)
- [pip package source selection](https://pip.pypa.io/en/stable/cli/pip_install/)
- [pip configuration](https://pip.pypa.io/en/stable/topics/configuration/)

The next pack is [Social Engineering](SOCIAL_ENGINEERING_REVIEW.md), delivered separately.
