# Active Directory review pack

**Post-v1.3.0 development capability.** This is bounded offline review of
selected, owner-normalized evidence. It is not a full AD penetration test or
an implementation of the upstream offensive techniques.

The [reference category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/active-directory)
contains both `offensive-active-directory` and `offensive-netexec`; the latter
is present even though the upstream README category count omits it. HunterQA's
implementation is original and does not install or execute upstream prompts,
scripts, collectors or security tools.

## What is implemented

| Skill / area | Offline review cues | What remains unverified |
| --- | --- | --- |
| `offensive-active-directory`: accounts | Selected UAC flags, contradictory enabled/disabled declarations, privileged service identities and delegation context | Actual credentials, service requirements, runtime policy, tickets and identity protections |
| `offensive-active-directory`: ACL | Selected ordinary-principal allow grants to Tier-0 objects; selected replication rights pair on domain objects | Canonical ACL, deny/inheritance rules, membership expansion and effective access |
| `offensive-active-directory`: AD CS | One compound declared template/enrollment configuration | CA permissions, exact EKUs, mapping, patches, issuance and complete ESC1–15 assessment |
| `offensive-active-directory`: trusts | Selected external/forest SID filtering and authentication scope declarations | Trust direction, effective filtering and legitimate design exceptions |
| `offensive-active-directory`: hybrid | Declared enabled synchronized identities privileged on-premises and in Entra | Actual assignments, synchronization, effective privilege and tenant boundaries |
| `offensive-netexec` | Selected domain-controller SMB signing, LDAP signing/channel binding and SMB1 declarations | Actual protocol negotiation, credentials, collection and other NetExec protocols/modules |

All findings are **unverified review candidates**, with remediation and neutral
case identifiers. INFO/WARNING are triage labels, not verified impact or CVSS
ratings. No domain, account, host, SID, DN, credential or raw configuration value
is copied into the report. Neutral IDs and unknown field names are retained.
Diagnostic text necessarily describes the selected configuration cue.

## Prepare normalized evidence

1. Establish permission to inspect the specific evidence. Start with owned lab
   snapshots and synthetic identities.
2. Copy [the JSON template](../templates/HunterQA-ad-review-template.json) and
   [the reviewer worksheet](../templates/07-active-directory-review.md) into a
   private directory outside this checkout.
3. A qualified directory owner must translate approved source observations into
   the exact fields below. This pack does **not** parse native BloodHound,
   ADExplorer, NetExec, LDIF, security descriptors or directory dumps. Do not
   paste those exports or command logs into the template.
4. Keep the identity-to-neutral-ID mapping private and separate. Never include
   passwords, hashes, tickets, keys, names, DNs or SIDs. Unknown fields are
   rejected rather than silently retained.
5. Replace only values supported by evidence. `null` and the enum `unknown`
   mean unassessed. `false` means an observed false setting, not missing data.
   Remove unavailable records or leave their values unknown. An untouched
   template reports insufficient evidence, not a successful assessment.
6. Record the snapshot time as timezone-aware ISO 8601 in `collected_at`, or use
   null if unknown. The report labels declared age over 24 hours and future time
   beyond five minutes for review; this is a freshness heuristic, not proof of
   collection or an authorization window.

## Field reference

All section arrays are required; an unused section may be empty. Every record
requires an `id` unique across all sections, matching `[a-z][a-z0-9-]{0,47}`.
Every listed observation field may be null.

| Section | Fields and interpretation |
| --- | --- |
| `accounts` | `enabled`, `tier0`, `is_domain_controller`: observed booleans; `kind`: user/service/computer/gmsa/unknown; `user_account_control`: unsigned 32-bit integer; `spn_count`: 0..10000. Tier-0 and DC status are owner-assigned context, not inferred from names or group membership. |
| `domain_controllers` | `smb_signing_required`, `ldap_signing_required`, `smb1_enabled`: booleans; `ldap_channel_binding`: always/when-supported/never/unknown. Supply effective server settings for the selected DC, not client defaults or guessed OS defaults. |
| `acl_grants` | `principal_tier`: ordinary/privileged/unknown; `target_tier`: tier0/other/unknown; `target_kind`: domain/group/user/computer/gpo/other/unknown; `effect`: allow/deny/unknown; `rights`: selected unique rights below, or null. Each record represents one owner-normalized grant, not the entire security descriptor. |
| `certificate_templates` | `published`, `broad_enrollment`, `enrollee_supplies_subject`, `authentication_eku`, `manager_approval`: booleans; `authorized_signatures`: 0..10000. Broad enrollment and authentication EKU eligibility must be established independently by the reviewer. |
| `trusts` | `kind`: external/forest/intra-forest/unknown; `sid_filtering_enabled`, `selective_authentication`: booleans. These are selected posture observations, not a calculation of cross-domain access. |
| `hybrid_accounts` | `enabled`, `synchronized`, `on_prem_privileged`, `entra_privileged`: booleans representing the same privately mapped identity. |

Selected ACL rights are GenericAll, GenericWrite, WriteDacl, WriteOwner,
AddMember, WriteSPN, ForceChangePassword, ReplicatingDirectoryChanges,
ReplicatingDirectoryChangesAll and ReplicatingDirectoryChangesInFilteredSet.
These are normalized labels, not a parser for raw ACE masks. Their presence
does not determine applicability to an object or usable effective permission.

Account checks use the [documented UAC flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties).
They review preauthentication, password requirements, reversible storage, DES,
password expiry, unconstrained delegation, protocol transition and selected
Tier-0 protections. Only declared-enabled, internally consistent accounts enter
these checks. Nonexpiring passwords are reviewed for user/service identities,
not gMSAs. Unconstrained delegation requires explicitly non-DC context because
DC behavior differs. Disabled, conflicting and unknown accounts are not proven
safe. SPN presence and delegation flags alone are not confirmed vulnerabilities.

SMB/LDAP checks reflect selected [SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview)
and [LDAP signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)
posture. The certificate predicate reviews published, broadly enrollable,
requester-supplied authentication identities with neither manager approval nor
authorized signatures. See [Microsoft's certificate posture guidance](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates).
The hybrid cue follows [privileged identity separation guidance](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts).
HunterQA does not change these settings; assess dependencies and compatibility
before independently approving remediation.

## Run on Kali/Linux

With the development checkout installed and environment activated:

```bash
mkdir -p "$HOME/hunterqa-cases/ad-review"
chmod 700 "$HOME/hunterqa-cases/ad-review"
cp templates/HunterQA-ad-review-template.json "$HOME/hunterqa-cases/ad-review/evidence.json"
chmod 600 "$HOME/hunterqa-cases/ad-review/evidence.json"
# Edit only the PRIVATE copy using independently reviewed source evidence.
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases/ad-review"
hunterqa ad-review-catalog
hunterqa ad-review \
  --input "$HOME/hunterqa-cases/ad-review/evidence.json" \
  --out "$HOME/hunterqa-cases/ad-review/review.json" \
  --authorized
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/ad-review/review.json" \
  --out "$HOME/hunterqa-cases/ad-review/review.sarif"
```

On Windows, use an access-controlled private directory and the platform's path
separator. Input must be an approved regular file; output requires an existing
approved parent and is private/create-only. Existing files are not overwritten.
Protect input evidence yourself; this command does not change input permissions.

The report retains exact input-byte SHA-256, UTC review time, declared freshness,
per-section record counts, unknown fields, candidate limits, skill states and
independent remediation guidance. It does not publish or upload reports.

## Bounds and limitations

Input is at most 1 MiB. There may be at most 200 accounts, 100 domain controllers,
200 selected ACL grants, 100 certificate templates, 100 trusts and 100 hybrid
records. At most 1000 findings are retained; `truncated` and
`candidates_not_retained` expose omitted candidates. Observations still record
all selected records. Scope completeness and directory coverage are not inferred.

No domain query, authentication, ticket collection, credential harvesting,
password attack, relay, directory replication, lateral movement, persistence,
evasion or directory modification is executed. No NetExec dependency is added.
This command is not a live workflow adapter or a native tool-output importer.

Unknown values and omitted sections remain visibly unassessed. Snapshot age,
owner declarations and hashes do not independently prove truth or consent.
An empty report or absence of findings is not an AD security certificate.
Real-world effectiveness remains unverified; tests use owned synthetic evidence.

**Following category: [Wireless](WIRELESS_REVIEW.md).** Its later offline policy
and hostapd-source review is separate from this AD pack and does not provide live
radio assessment capabilities.
