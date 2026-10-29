# IoT & Embedded review pack

**Post-v1.3.0 development capability.** The `offensive-iot` contract provides
selected local evidence review and two bounded text readers. It is not a complete
IoT/OT penetration test, firmware analyzer or hardware testing engine.

The category vocabulary references [Claude-Red](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/iot).
HunterQA's implementation is original; upstream payloads, scripts and hardware
procedures are not imported, installed or executed.

## Coverage and uncertainty

| Input | Implemented | Requires independent work |
| --- | --- | --- |
| Owner-normalized JSON | Nine areas of nullable control observations | Collection, authenticity, applicability and actual enforcement |
| Mosquitto ACL text | Selected topic/pattern rules, wildcard scope and section context | Broker configuration/authentication, plugins, deny precedence and effective access |
| Resolved U-Boot `.config` | Four selected explicit build flags and missing fields | Build provenance, required keys, trust anchors, all boot paths and installed artifact |

INFO/WARNING are unverified review cues, not confirmed impact or CVSS ratings.
Broad topic permissions and compiled maintenance features can be intentional.
Quiet output does not establish security. All seven broader readiness areas remain
partial, and independent real-world effectiveness is unverified.

No device, serial/debug interface, radio, broker, CoAP server or industrial
controller is contacted. No firmware is acquired, unpacked, mounted or executed.
There is no credential testing, secret extraction, console command execution,
boot modification, fault injection, industrial write or bypass operation.

## 1. Prepare private evidence

After merging and pulling the change, activate the development environment and run
`python -m pip install -e .`. No new dependency, hardware driver, broker, SDK or
firmware extraction tool is needed for this pack.

Use private copies of [the JSON template](../templates/HunterQA-iot-review-template.json)
and [review worksheet](../templates/11-iot-embedded-review.md), outside the checkout.
Keep owner approval, source files and neutral-ID mapping separate and private.
The authorization flag is an operator attestation, not verified owner consent.

```bash
umask 077
mkdir -p "$HOME/hunterqa-cases/iot"
cp templates/HunterQA-iot-review-template.json "$HOME/hunterqa-cases/iot/evidence.json"
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases/iot"
# Edit only the private copy using applicable, independently reviewed evidence.
hunterqa iot-review-catalog
hunterqa iot-review \
  --input "$HOME/hunterqa-cases/iot/evidence.json" \
  --out "$HOME/hunterqa-cases/iot/review.json" \
  --authorized
```

Set every observation to true, false or null. Null means unknown/unassessed;
false means the owner explicitly observed the control absent or review incomplete.
Do not replace unknowns with reassuring values. Remove inapplicable records.
An untouched template reports insufficient evidence, not a pass.

| Area | Required observation fields |
| --- | --- |
| Hardware | `debug_access_controlled`, `sensitive_interfaces_reviewed`, `physical_access_policy_reviewed` |
| Firmware | `provenance_verified`, `embedded_secrets_reviewed`, `component_patch_reviewed` |
| Boot | `boot_chain_verified`, `trust_anchor_protected`, `alternate_boot_paths_reviewed` |
| Updates | `update_authenticity_verified`, `rollback_policy_reviewed`, `recovery_process_reviewed` |
| MQTT | `client_authentication_required`, `topic_authorization_reviewed`, `transport_protected` |
| CoAP | `peer_authentication_required`, `resource_authorization_reviewed`, `transport_or_object_security_reviewed` |
| Industrial | `management_network_segmented`, `write_operations_authorized`, `safety_impact_reviewed` |
| Lifecycle | `unique_credentials_verified`, `decommissioning_reviewed`, `security_event_logging_reviewed` |
| Ecosystem | `companion_authorization_reviewed`, `cloud_identity_scope_reviewed`, `device_identity_binding_reviewed` |

The root has exactly `schema_version: 1` and `records`. Each record has exactly
`id`, `area`, `observations`. Neutral IDs are unique and match
`[a-z][a-z0-9-]{0,47}`. All fields listed for the chosen area are required;
unknown values are null. At most ten records per area and 90 total are accepted.
These observations do not identify CVEs or verify protocol/version applicability.
CoAP observations allow transport or object security; lack of DTLS alone is not
automatically an issue. Industrial observations do not validate a safety case.

## 2. Review a selected Mosquitto ACL file

Supply an already collected, approved ACL file, not `mosquitto.conf`, password
files, dynamic-security JSON or a log. Do not upload real ACLs to GitHub.

```bash
hunterqa iot-config-review \
  --mode mqtt-acl \
  --input "$HOME/hunterqa-cases/iot/broker.acl" \
  --out "$HOME/hunterqa-cases/iot/acl-review.json" \
  --authorized
```

The selected grammar accepts `user NAME`, `topic [read|write|readwrite|deny] FILTER`
and `pattern [read|write|readwrite|deny] FILTER`. Omitted access is readwrite.
Comments begin with `#` in column one; inline comments are not stripped. Blank
lines are accepted; indented directives/comments and unsupported directives are
rejected. No includes, plugins or referenced files are loaded.

Filters are a selected subset: no whitespace, at most 1024 UTF-8 bytes, `+` as a
whole level and `#` only as the last whole level. Pattern `%u` and `%c` must occupy
a whole level; other percent-containing filters are outside this reader's subset.
Username text is limited to 256 characters and is never exported. There are at
most 128 user sections and 400 rules. Rules stay in source order; no permissions
are merged, denied/allowed or simulated across them.

Review cues cover root wildcards, wildcard publishing, patterns without selected
identity substitutions, allow rules before a user section and system-topic write
scope. Deny rules are retained as context without allow cues. Patterns are global
regardless of the preceding user section. Root wildcards do not establish access
to dollar-prefixed system topics. Pre-user rules do not prove anonymous clients
can connect. Client-ID substitution does not prove authenticated identity.

## 3. Review selected U-Boot build declarations

Use an owner-selected final, resolved U-Boot `.config` for the relevant build.
This command does not merge defconfig/fragments, resolve Kconfig dependencies,
identify a firmware version or prove the file belongs to an installed artifact.

```bash
hunterqa iot-config-review \
  --mode uboot-config \
  --input "$HOME/hunterqa-cases/iot/uboot.config" \
  --out "$HOME/hunterqa-cases/iot/boot-review.json" \
  --authorized
```

The four selected booleans are `CONFIG_FIT`, `CONFIG_FIT_SIGNATURE`,
`CONFIG_LEGACY_IMAGE_FORMAT`, `CONFIG_CMD_MEMORY`. Explicit `y`, `n` and generated
`# CONFIG_NAME is not set` declarations are recognized. Duplicate symbols,
invalid selected values, source directives and non-assignment syntax are rejected.
Other `CONFIG_NAME=VALUE` declarations are counted without exporting or interpreting
their values; this is not a full Kconfig parser or a secret detector.

Explicitly disabled FIT signature support, compiled legacy-image support and
memory commands produce INFO review cues. Other boot verification mechanisms
may exist. Enabled FIT signature support also produces an INFO reminder to verify
mandatory keys, trust-anchor protection and alternate boot paths independently.
It is not marked as successful verified boot. Missing flags remain unknown.

## Reports and verification

Inputs must be approved regular files, at most 1 MiB. Native text must be UTF-8,
with no unsupported control characters, at most 20,000 lines and 4096 characters
per line. Native readers reject unsupported input with contents withheld.
At most 500 findings are retained; truncation and dropped counts are explicit.

Reports retain UTC time, exact input SHA-256, neutral/receipt-derived case IDs,
source line numbers for native rules, unknown fields, remediation and unverified
status. Native IDs change with input bytes/order. Topics, usernames and unselected
build contents are omitted. Normalized IDs are supplied by the operator; use
neutral labels. A hash is not proof of consent, provenance or authenticity.
Runtime enforcement and signature verification flags remain false.

Outputs use the existing private, create-only writer: their parent must exist
inside approved roots, and existing files are not overwritten. On Windows use an
access-controlled private case directory. Input permissions remain your responsibility.
Use the existing source-free exporter locally:

```bash
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/iot/review.json" \
  --out "$HOME/hunterqa-cases/iot/review.sarif"
```

Tests use owned synthetic JSON/ACL/build fixtures and positive/negative controls.
They establish parser/review behavior, not real-device detection rates, effective
broker access, signed-image verification, full NIST compliance or OT safety.

## Primary references and next category

- [Mosquitto ACL syntax](https://mosquitto.org/man/mosquitto-conf-5.html)
- [U-Boot FIT signatures](https://docs.u-boot.org/en/latest/usage/fit/signature.html) and [verified-boot design](https://docs.u-boot.org/en/latest/usage/fit/verified-boot.html)
- [CoAP specification](https://www.rfc-editor.org/rfc/rfc7252.html)
- [NIST IoT capability baseline](https://csrc.nist.gov/pubs/ir/8259/a/final)

**Next requested category: Infrastructure & Red Team.** It is not delivered here.
