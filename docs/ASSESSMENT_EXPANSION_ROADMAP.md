# Assessment expansion: delivery and acceptance gates

This tracks the seven requested gaps. **The platform is not complete across these
areas.** Development includes scoped HTML discovery, four additional fixed
assessment adapters, shared host-local quotas and a versioned owned application
benchmark. None changes the immutable published v1.3.0 release. See
[setup and boundaries](ASSESSMENT_ADAPTERS.md), or run `hunterqa coverage-audit`.

The newer [owned scenario milestone](SCENARIO_ASSESSMENTS.md) implements reviewed
actions, encrypted target sessions, explicit workflow contracts, SQL/XSS context
fixtures, SSRF callback/upload cleanup, service observations and normalized
AD/cloud permission models. Completed CLI evidence now links to projects in the
dashboard. The original sequencing table below remains a broad acceptance
roadmap; general coverage and external enterprise/cloud validation remain open.
The newer [unified increment](ASSESSMENT_MODES.md) adds actual isolated Samba
LDAPS acceptance and bounded AWS inventory; these do not complete broad AD/IAM
coverage. Current item-level status is in the [traceability matrix](PLATFORM_GAP_ANALYSIS.md).

| Priority | Area | Current delivery | Next acceptance gate |
| --- | --- | --- | --- |
| P0 | Website discovery | Bounded HTML/rendered anchors and explicitly selected SPA slash hash routes, ephemeral conventional login and separate discovered/visited reference recall | General SPA actions, complex sessions/SSO and representative route-coverage evaluation |
| P0 | Platform hardening | Separate process/workspace stores, explicit operator OIDC/local roles, authenticated HTTPS edge, bounded WSGI/scan admission, local lease/recovery and selected host-local quotas | Real provider/deployment acceptance, independently verified owner grants, independently validated OS/tenant isolation and denied egress, cross-host quotas and distributed workers |
| P0 | Detection effectiveness | Eight versioned owned application cases, retained evidence, source/label hashes and per-class metrics; existing source/header/cookie controls | Externally reviewed ground truth, representative real-world datasets, detection rates across remaining classes and standards coverage |
| P1 | Active vulnerability validation | SQL boolean contexts, HTML/attribute/DOM Chromium witnesses, owned SSRF callback, inert upload cleanup and timing signals | General context-specific validation, real DBMS blind SQL, stored XSS, broad SSRF/upload and traversal coverage |
| P1 | Authentication/authorization | Multi-role/anonymous GET contracts, optional offline signed ID-token verification and owned OIDC/session controls | External SSO, complex sessions, stateful business workflows and general tenant-boundary discovery; status matches alone are insufficient |
| P2 | Infrastructure/network | Exact TCP/TLS/UDP tools, fixed service observations, normalized candidate paths and bounded Samba-tested LDAPS | General service/OS assessment, broader UDP, effective AD ACL/GPO/trusts and executed access-path testing |
| P2 | Cloud runtime | AWS identity/account counters and bounded EC2/security-group/S3 metadata, Azure/GCP inventories and selected GCP permission queries | Representative sandbox-account validation, complete resource and independently confirmed effective-permission inventory, and broader provider coverage |

## Implementation sequence

1. Review the [scoped discovery](SCOPED_WEB_DISCOVERY.md) and
   [assessment adapter contracts](ASSESSMENT_ADAPTERS.md); all seven areas remain partial.
2. Extend the versioned owned assessment lab with externally reviewed labels and
   representative applications; preserve negative controls and publish unknowns.
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

See [expansion progress](EXPANSION_PROGRESS.md) for each delivered increment.
Current native TLS/SSH/DNS/Azure/GCP commands share the optional host-local
ledger; legacy entry points, cross-host enforcement and tenant isolation remain
outside its coverage.

This roadmap does not include credential theft, covert persistence, security-tool
evasion, data exfiltration or anti-forensics automation. It supports authorized
assessment and evidence collection without promising comprehensive discovery,
automatic CVE allocation or guaranteed zero-days.
