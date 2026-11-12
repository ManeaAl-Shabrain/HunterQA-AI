# Assessment architecture decisions

## Preserve the existing platform

The baseline is merged main `b4f9dba`. Historical analytics/infrastructure branches
were inspected before changes, rather than blindly merged. Existing SAST, OpenAPI,
CVE, fuzzing, AI, evidence, workflow, dashboard and authentication components remain
in place. The requirement matrix was committed before implementation.

## Separate origin, execution and validation

DEMO/LAB/LIVE describes source intent. Implementation status, local test evidence
and provider validation are separate. Imported files never establish actual live
collection. A matched workflow, uploaded text file, open port, banner, timing
signal or broad declaration is not automatically a confirmed vulnerability.
Missing evidence remains unknown; no calibrated confidence probability is invented.

Original collector reports are retained, and the shared facade links their exact
file hashes. Existing report schemas are not retroactively marked LIVE. Mixed
source correlation preserves source labels and means matching digests only.

## Reuse analysis and security boundaries

The shared facade calls the original analyzers and authorized collectors. It does
not replace their scopes, credentials, approvals, time windows, budgets or stop
controls. The new business-event reviewer evaluates explicit typed rules and
observations; it does not evaluate arbitrary expressions or execute transactions.

Credential encryption reuses the existing private store and authenticated
encryption, with distinct protected purposes for web sessions, LDAP readers,
AWS signing and Azure/GCP temporary tokens. A purpose cannot be changed by editing wrapper metadata. Legacy
web-session files remain compatible. No personal account or secret is embedded.

## Keep network execution behind the existing local operator boundary

The dashboard can start bounded offline demos using the existing role/CSRF/audit
gates and private project history. Network collection remains a typed CLI action
under the established local operator boundary. A general HTTP target-execution
API or distributed job queue is not introduced as a shortcut.

Complete dashboard-driven LAB/LIVE execution and progress would require an
explicit preapproved-workflow control plane, credential delegation, durable
cancellation/recovery and additional isolation review. This is an outstanding
implementation requirement, not an external-account test blocker. Existing source
scan execution/progress and workflow history remain usable.

## Bound collection and retain uncertainty

LDAPS requires verified TLS, a pinned numeric endpoint, exact naming context and
critical domain-scope control; no referral/range fallback or directory writes.
AWS uses fixed commercial read APIs, STS account matching, explicit short-lived
signing credentials and origin-bound actors. The SDK never discovers credentials
or sends requests. Resource/page/size/deadline limits are intentional coverage
limits, not a claim of complete inventory.

Actual Samba AD runs in a disposable network-none container, with a non-admin
directory reader and unprivileged assessment process. Test-only server provision
needs root inside that container; the helper refuses native-host operation.
Synthetic unit tests, actual owned TLS, actual Samba, Linux deployment and future
real cloud/provider tests are reported separately.
