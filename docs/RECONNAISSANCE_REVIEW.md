# Reconnaissance review pack

**Post-v1.3.0 development capability.** Two offline contracts review OSINT evidence
and methodology. A bounded name importer builds a deduplicated inventory only from
previously collected names matching an explicit local domain scope. It does not
collect intelligence, query DNS/CT, contact services or enroll active targets.

The vocabulary references [Claude-Red's Recon category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/recon).
HunterQA's implementation is original. Upstream instructions, tools and collection
scripts are not imported, installed or executed.

## Coverage

| Contract | Selected owner observations |
| --- | --- |
| `offensive-osint` | Scope, source provenance, asset attribution and data minimization review |
| `offensive-osint-methodology` | Collection plan, corroboration, evidence timestamps and retention review |

These are declarations, not independent verification. INFO findings are review
cues, not confirmed vulnerabilities or impact ratings. All broad readiness areas
remain partial; real-world effectiveness is unverified. No people profiling,
email/credential harvesting, breach lookup, code search or third-party collection
tool is implemented here.

## 1. Private evidence review

After merging and pulling, activate the development environment and run
`python -m pip install -e .`. No new dependency or external service is needed.
Copy [the review JSON](../templates/HunterQA-recon-review-template.json),
[name-scope JSON](../templates/HunterQA-recon-scope-template.json) and
[worksheet](../templates/15-reconnaissance-review.md) outside this checkout.
Keep approvals, asset mapping and original evidence private.

```bash
umask 077
mkdir -p "$HOME/hunterqa-cases/recon"
cp templates/HunterQA-recon-review-template.json "$HOME/hunterqa-cases/recon/evidence.json"
cp templates/HunterQA-recon-scope-template.json "$HOME/hunterqa-cases/recon/name-scope.json"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases/recon"
# Edit private copies using approved evidence and exact owner-approved domains.
hunterqa recon-review-catalog
hunterqa recon-review \
  --input "$HOME/hunterqa-cases/recon/evidence.json" \
  --out "$HOME/hunterqa-cases/recon/review.json" \
  --authorized
```

Review JSON has exactly `schema_version: 1` and `records`. Each record has exactly
`id`, `skill`, `observations`; catalog/template list the exact required fields.
Neutral IDs are unique and match `[a-z][a-z0-9-]{0,47}`. Observations are boolean
or null. False records an incomplete review; null means unknown. An untouched
template reports insufficient evidence, not a pass. Remove inapplicable records.
Maximum ten records per contract, 20 total.

## 2. Declare the separate name-import scope

The private name-scope file has exactly this shape:

```json
{
  "schema_version": 1,
  "domains": [
    {"name": "example.test", "include_subdomains": false}
  ]
}
```

Replace the example only with approved domains. `include_subdomains` must be
explicitly true or false. False admits the exact canonical hostname only; true
also admits descendants across dot-separated label boundaries. Rules form a union.
At most 20 rules are accepted; duplicate canonical roots are rejected. No public
suffix discovery, registrable-domain guessing or ownership lookup is performed.

Scope names must be ASCII DNS names with at least two labels. Case and one terminal
dot are normalized. Labels allow letters, digits and internal hyphens, at most
63 characters; complete canonical names are at most 253 characters. IP addresses,
all-numeric dotted forms, URLs, ports, paths, email addresses, wildcard roots,
underscores and Unicode labels are outside this selected subset. ASCII punycode
labels are retained without Unicode conversion or IDNA validity verification.

This name-import scope is **not** the existing assessment profile/target schema.
It cannot authorize network access or grant active-workflow permissions. Operator
attestation and domain matching do not independently verify owner consent.

## 3. Import previously collected names

For a plain UTF-8 file containing one name per nonblank line:

```bash
hunterqa recon-inventory \
  --mode names \
  --scope "$HOME/hunterqa-cases/recon/name-scope.json" \
  --input "$HOME/hunterqa-cases/recon/owner-names.txt" \
  --out "$HOME/hunterqa-cases/recon/inventory.json" \
  --authorized
```

Outer whitespace is trimmed. This format has no comment syntax. At most 2000
lines, 1024 characters per line and 1000 unique admitted names are accepted. Name
syntax uses the same selected rules as the scope, with one additional supported
form: a leading `*.` wildcard pattern. No wildcard is expanded or converted into
exact targets. A wildcard is admitted only when its entire suffix is covered by
an explicit subdomain-enabled rule; a broad pattern cannot match a narrower root.
DNS/TLS wildcard semantics are not evaluated.

For a saved CT-style JSON name export, use `--mode ct-names-json`. Input is an array
of at most 500 objects, each containing a string `name_value`. Only that field is
interpreted; common names, issuer identities, certificate metadata and other fields
are ignored. `name_value` may contain newline-separated names: at most 8192
characters and 100 name lines per object, 2000 nonblank candidate names total.
An empty array is valid but insufficient evidence. This selected reader is not a
complete third-party API adapter, certificate parser or CT protocol implementation.

Malformed input shapes/duplicates/bounds are rejected with contents withheld.
Individual invalid names and valid names outside scope are counted and omitted.
Only admitted names are deduplicated after case/terminal-dot normalization.
Repeated observations retain up to ten source references per name; additional
reference counts remain explicit. Names, commands and URLs from other fields are
never opened, executed or requested.

## Privacy and reports

Default inventory output withholds names, retaining canonical-name SHA-256 and
neutral case IDs. Hashes can be correlated or guessed and do not provide anonymity.
For a usable private inventory containing admitted canonical names, add
`--include-names` explicitly. Invalid and out-of-scope names remain omitted even
with this option. Never upload named inventories or filled case files to GitHub.

Reports retain UTC time, exact input and scope byte hashes, unknown fields,
admission/duplicate counts and source references. In text mode `source_row` is the
original line number; in CT mode it is the object index, and `name_index` is the
line index within `name_value`. Aggregate findings do not claim exact source
coordinates; the SARIF exporter uses an external-evidence placeholder. Findings
retain receipt-derived context; asset IDs derive from canonical names.

No admitted name is proof of current ownership, DNS existence, service exposure
or a vulnerability. Certificate-name text needs independent provenance, timing
and attribution review. No certificate signature, transparency proof, chain or
current DNS binding is verified. Imported names are never enrolled in active
testing automatically; obtain independently approved exact targets and use the
existing assessment workflow separately.

All files must be approved local regular files of at most 1 MiB. Both inventory
input and scope must be inside `HUNTERQA_APPROVED_ROOTS`. Input paths and referenced
content are not recursively followed. Outputs use the existing private/create-only
writer: approved parents must exist, and existing files are never overwritten.
On Windows use an access-controlled private case directory; secure inputs yourself.

```bash
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/recon/inventory.json" \
  --out "$HOME/hunterqa-cases/recon/inventory.sarif"
```

Tests use synthetic reserved-domain fixtures, including positive/negative scope
boundaries, unknown declarations, malformed imports, privacy and non-overwrite.
They do not establish live collection effectiveness or complete attack-surface coverage.

## References and next category

- [X.509 name representation background](https://www.rfc-editor.org/rfc/rfc5280.html)
- [Certificate Transparency background](https://www.rfc-editor.org/rfc/rfc9162.html)

The next category now has a separate [API Security review guide](API_SECURITY_REVIEW.md).
Its local contract/evidence checks do not extend this Recon pack into active API testing.
