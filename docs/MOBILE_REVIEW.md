# Mobile review pack

**Post-v1.3.0 development capability.** The `offensive-mobile` contract adds
selected offline Android/iOS evidence and decoded XML configuration review.
It does not implement the complete offensive methodology or a device pentest.

The vocabulary references [Claude-Red's Mobile category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/mobile).
HunterQA's implementation is original. Upstream prompts, payloads, dynamic hooks,
extraction scripts and bypass tooling are not imported, installed or executed.

## Coverage

| Mode | Selected coverage | Not delivered here |
| --- | --- | --- |
| Normalized Android/iOS evidence | Storage, transport, WebView, authentication, links, IPC and build declarations | Actual storage, key protection, biometric, session, signing or runtime validation |
| Android Manifest XML | Explicit app flags, export declarations, browsable link-handler declarations and selected custom-permission levels | Manifest merging, resources, implicit export/default rules, effective permissions and component invocation |
| Android Network Security Config XML | Explicit cleartext scopes, user CA trust, pin overrides and past pin-set expiration dates | Domain inheritance, platform precedence, actual TLS trust/pinning or networking behavior |
| iOS Info.plist XML | Selected ATS exceptions, domain transport relaxations, sharing and URL-scheme declarations | ATS effective OS behavior, network requests, association validation and sensitive-data access |
| iOS entitlements XML | Debugger task access, selected sharing/association capabilities and private entitlement declarations | Actual code signature, provisioning eligibility, granted capabilities or shared storage access |

INFO/WARNING are **unverified triage cues**, not demonstrated impact or CVSS
ratings. Exported components, link handlers, sharing and transport exceptions
can be intentional. Missing flags do not prove secure defaults. Source files do
not prove installed application behavior, authentic signing or owner consent.
Real-world detection effectiveness remains unverified.

## Update the development installation

The secure XML reader `defusedxml` is now a core dependency. After pulling the
merged change, reactivate the environment and refresh the editable installation:

```bash
python -m pip install -e .
python -m pip check
```

The `cloud` extra continues to supply botocore for the existing approved AWS
adapter; its XML dependency is supplied by the core installation. No Android/iOS
SDK, adb, emulator, Frida, Objection, apktool or Xcode is required for this pack.

## Mode A — owner-normalized evidence

Copy [the JSON template](../templates/HunterQA-mobile-review-template.json) and
[private worksheet](../templates/10-mobile-review.md) outside this checkout.
Populate only observations supported by approved evidence. Keep original source,
identities and the neutral-ID mapping private and separate.

Top-level fields are exactly `schema_version: 1` and `records`. Each record has
`id`, `platform` (android/ios), `area` and `observations`. Neutral IDs are unique
and match `[a-z][a-z0-9-]{0,47}`. Every observation is boolean or null:

| Area | Required observation fields |
| --- | --- |
| Storage | `sensitive_data_protected`, `secrets_in_logs`, `backup_policy_reviewed` |
| Transport | `tls_validation_enforced`, `cleartext_permitted`, `pinning_policy_reviewed` |
| WebView | `untrusted_content_allowed`, `native_bridge_restricted`, `file_access_restricted` |
| Authentication | `biometric_authentication_used`, `biometric_crypto_binding`, `session_revocation_reviewed`, `local_authorization_reviewed` |
| Links | `input_validation_reviewed`, `ownership_association_verified`, `sensitive_action_requires_auth` |
| IPC | `exported_surface_reviewed`, `sender_authentication_reviewed`, `least_privilege_reviewed` |
| Build | `production_debug_disabled`, `release_signing_verified`, `dependency_patch_reviewed` |

Null means unknown/unassessed; false means an observed false setting. Do not set
true merely to silence a finding. Remove unavailable/inapplicable records. An
untouched template reports insufficient evidence, not a pass. WebView bridge
cues require declared untrusted content; biometric-binding cues require declared
biometric use. Missing pinning alone is not automatically a vulnerability.

On Kali/Linux, with the development environment active:

```bash
mkdir -p "$HOME/hunterqa-cases/mobile"
chmod 700 "$HOME/hunterqa-cases/mobile"
cp templates/HunterQA-mobile-review-template.json "$HOME/hunterqa-cases/mobile/evidence.json"
chmod 600 "$HOME/hunterqa-cases/mobile/evidence.json"
# Edit only the PRIVATE copy using independently reviewed source evidence.
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases/mobile"
hunterqa mobile-review-catalog
hunterqa mobile-review \
  --input "$HOME/hunterqa-cases/mobile/evidence.json" \
  --out "$HOME/hunterqa-cases/mobile/review.json" \
  --authorized
```

On Windows, use an access-controlled private directory and the platform's path
separator for multiple roots. Inputs must be approved regular files. Outputs
require an existing approved parent, are private/create-only and never overwrite
existing files. Secure input permissions yourself; these commands do not alter them.

## Mode B — decoded configuration XML

Use a private, authorized, already-decoded source artifact. **Do not upload real
files**: they can contain app identities, domains, keys, user data or tokens.
This pack does not retrieve, unpack or decode APK/IPA/binary XML/binary plist.
Any necessary extraction/conversion must be separately approved and performed
with appropriate trusted tools outside this command.

```bash
hunterqa mobile-config-review \
  --mode android-manifest \
  --input "$HOME/hunterqa-cases/mobile/AndroidManifest.xml" \
  --out "$HOME/hunterqa-cases/mobile/manifest-review.json" \
  --authorized
```

Select exactly one mode:

- `android-manifest`: a decoded `<manifest>` with one `<application>` and normal
  Android attribute namespace. Explicit true flags reviewed are debuggable,
  allowBackup, usesCleartextTraffic, testOnly and requestLegacyExternalStorage.
  Absent/resource-placeholder booleans remain unknown; no defaults are guessed.
  Components marked exported generate INFO surface-review cues, not access-bypass
  findings. Missing export contracts on filtered components do not imply exposure:
  SDK/build rules may instead prevent installation. Selected VIEW/BROWSABLE data
  handlers and normal/dangerous custom permission definitions need context review.
  Permission names, component names, package identifiers and URLs are withheld.
  Referenced Network Security Config and backup/extraction rules are noted but
  never opened; supply separate explicit inputs for supported source review.
- `android-network-security`: a decoded `<network-security-config>` with 1..100
  selected base-config/domain-config/debug-overrides elements. Each explicit scope
  is reviewed independently; inheritance/precedence is not calculated. User-CA
  trust inside debug overrides is INFO and applies only in the appropriate debug
  context. Explicit pin overrides and past expiration dates require independent
  maintenance/applicability review. Expired pinning does not mean normal TLS trust
  is disabled. Pin values, certificate contents and domain names are not exported.
- `ios-info`: XML `<plist version="1.0">` containing one dictionary. Selected ATS
  keys, exception-domain settings, document sharing/open-in-place flags and URL
  scheme declarations are reviewed. Global ATS exceptions can have different
  precedence across OS versions and more-specific keys; a global true flag does
  not establish that all connections permit cleartext. URL schemes are not opened
  and association domains are not requested.
- `ios-entitlements`: the same XML plist shape, containing source entitlement
  declarations. Selected debugger, sharing, association and private capabilities
  are review cues only. Actual signed entitlements, provisioning and platform
  eligibility are not verified. No keychain or shared container is accessed.

XML parsing forbids entity declarations and external references. Android modes
also reject DOCTYPE declarations. XML plists permit a DOCTYPE declaration for
standard Apple files, but do not retrieve its external DTD; entities remain
forbidden. XInclude is rejected. Duplicate plist dictionary keys and unsupported
selected value types are rejected with contents withheld, including chained
conversion errors. Unselected plist data/date values are opaque, not decoded or
exported. These are selected readers, not complete platform schema validators.

## Reports, limits and validation

Reports retain neutral/receipt-derived case IDs, platform/context, unknown fields,
UTC review time, exact input-byte SHA-256, candidates and remediation. Native case
IDs change with input bytes/record order. XML parser line coordinates are not
claimed; privately map case context/order back to the original source. Source
identifiers, names, domain/scheme values, pins and credentials are omitted.
Diagnostic text necessarily describes the selected declaration. Protect reports
and evidence; a hash does not independently prove authenticity or consent.

Input is at most 1 MiB. Normalized evidence allows 10 records per platform/area,
140 total. XML is bounded to 5000 nodes and depth 32. Selected native limits are
200 Android components, 100 custom permissions, 100 network-config scopes,
100 iOS exception domains and 100 items per selected plist array. At most 500
findings are retained; truncation and dropped counts remain visible.

Flags explicitly state that runtime enforcement and signatures were not verified.
Network requests, device actions, external tools and referenced-file reads remain
zero. No installation, interception, rooting/jailbreaking, process hook, pinning
bypass, biometric bypass, secret extraction or app repackaging occurs.

Use the existing source-free SARIF exporter, without uploading:

```bash
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/mobile/review.json" \
  --out "$HOME/hunterqa-cases/mobile/review.sarif"
```

Tests use owned synthetic decoded XML/JSON and plist fixtures, not installed
applications, devices or backend APIs. Static findings, owner declarations and
quiet output do not establish real-world detection rates or complete MASVS coverage.

## Primary references and next category

- [Android application declarations](https://developer.android.com/guide/topics/manifest/application-element) and [Network Security Config](https://developer.android.com/privacy-and-security/security-config)
- [Apple ATS documentation](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity) and [entitlement verification background](https://developer.apple.com/library/archive/technotes/tn2415/_index.html)
- [defusedxml parser protections](https://github.com/tiran/defusedxml)

The next category now has a separate [IoT & Embedded review guide](IOT_EMBEDDED_REVIEW.md).
Its local evidence/source checks do not extend this Mobile pack into device or
runtime testing.
