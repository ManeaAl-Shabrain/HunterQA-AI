# Mobile — private reviewer worksheet

Copy outside the public checkout. Read [the Mobile guide](../docs/MOBILE_REVIEW.md).
This worksheet is a human record, not an authorization grant or device test plan.
Keep package/bundle IDs, component names, domains, signing identities, user data
and neutral-ID mappings in separate private evidence. Never include keys/tokens.

- Written permission and selected artifact/evidence scope: `<private reference>`
- Reviewer / UTC date: `<reviewer and date>`
- Android/iOS build, source revision, OS/API context and collection time: `<private references>`
- Exact decoded artifact/input hash and private source mapping: `<references>`
- Private report path and unsupported/missing evidence: `<record>`

| Review area | Independent evidence needed | Decision / private reference |
| --- | --- | --- |
| Storage | Sensitive data, actual file protection, Keystore/Keychain access, logging and backup behavior | Not assessed |
| Transport | Actual TLS validation, network stack, ATS/Network Security Config precedence and approved exceptions | Not assessed |
| WebView | Actual content origins, navigation, file access, native bridge and origin authorization | Not assessed |
| Authentication | Protected operations, biometric/cryptographic binding, sessions and server-side authorization | Not assessed |
| Links | Actual handler inputs, App Links/Universal Links ownership, fallback and sensitive-action authorization | Not assessed |
| IPC | Final merged/signed surface, actual caller identity, permissions and authorization | Not assessed |
| Build | Intended release type, actual signing/provisioning and independently applicable component updates | Not assessed |

For decoded Android XML, review the final manifest/build and explicit resource
files together; this tool does not resolve their references or platform defaults.
For iOS XML plists, compare source declarations with the actual code signature,
provisioning and supported OS behavior. A declared capability is not proof that
the installed application can exercise it.

Use **not assessed**, **reviewed with no issue observed**, **candidate**, or
**validated finding**. Only mark a finding validated after independent approved
reproduction and impact review. Empty findings and missing flags are not a pass.

For each candidate retain: rule/case ID, exact source revision and private mapping,
expected/observed behavior, false-positive/applicability review, independent
authorized validation, impact, remediation, reviewer decision and fresh retest.
These commands do not install apps, open links, access devices, intercept TLS,
extract storage/keychains, hook processes or bypass device/app protections.
