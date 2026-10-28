# Assessment expansion: delivery and acceptance gates

This tracks the seven requested gaps. **The platform is not complete across these
areas.** The first development increment adds scoped HTML discovery; it does not
change the published v1.3.0 release or silently enable other assessment modes.

| Priority | Area | Current delivery | Next acceptance gate |
| --- | --- | --- | --- |
| P0 | Website discovery | Bounded unauthenticated HTML link following, form inventory, scope/pacing/quota controls and private evidence | Add owned SPA fixtures and explicit browser request admission before JavaScript/session coverage; measure reachable-route coverage |
| P0 | Platform hardening | Existing supervised fixed workers, local approval fingerprints, per-run quotas, stop/timeout controls | Independently verified owner grants and authenticated roles; an OS sandbox with denied egress tests; shared quota ledger before distributed workers |
| P0 | Detection effectiveness | Synthetic positive/negative source controls; new header/cookie controls and real loopback discovery boundary tests | Versioned owned vulnerable applications, independently labeled ground truth, per-class recall/false positives and reproducibility manifest; publish limitations |
| P1 | Active vulnerability validation | Existing exact observations, separate narrow approved account/browser checks and offline evidence import | Individually specified non-destructive validators with explicit approval, positive/negative fixtures, response redaction and cancellation tests before enabling each class |
| P1 | Authentication/authorization | Separate dedicated-account form checks; manual review workflows | Explicit role-pair fixtures, isolated sessions, expected-access matrix and no cross-role credential leakage; SSO and business logic need application-specific assertions |
| P2 | Infrastructure/network | Declared inventory and offline service-evidence import | Reviewed enumeration adapter with exact host/port admission and service impact controls; isolated AD fixtures and evidence import before broader attack-path claims |
| P2 | Cloud runtime | Selected local configuration/dependency patterns | Read-only provider adapters, scoped identities, account/project binding, pagination and cost budgets; provider-specific fixtures and denied-write tests |

## Implementation sequence

1. Ship and review the [scoped discovery increment](SCOPED_WEB_DISCOVERY.md).
2. Establish the versioned owned assessment lab and coverage manifest; report
   unknown or untested classes explicitly, including negative controls.
3. Implement hardening foundations before adding external tool execution or
   multiple operators. Treat local operator attestations as attestations until
   verified grants and authenticated roles actually exist.
4. Add one narrowly defined validation adapter at a time, with authorization bound
   to its exact parameters, budgets and window. Findings remain unverified until
   evidence satisfies that adapter's documented validation contract.
5. Add role-pair authorization checks and application-specific business workflows.
6. Add read-only cloud and bounded infrastructure adapters separately, with owned
   lab acceptance tests and clearly documented provider/protocol coverage.
7. Add distributed execution only after shared admission, quota, cancellation and
   evidence integrity are tested across workers and failures.

Every increment needs reproducible tests, documented inputs and output limits,
honest coverage statements, evidence handling, and compatibility checks. A catalog
entry, imported finding, checklist, or passing synthetic test alone does not make
a vulnerability class implemented or prove real-world detection effectiveness.

This roadmap does not include credential theft, covert persistence, security-tool
evasion, data exfiltration or anti-forensics automation. It supports authorized
assessment and evidence collection without promising comprehensive discovery,
automatic CVE allocation or guaranteed zero-days.
