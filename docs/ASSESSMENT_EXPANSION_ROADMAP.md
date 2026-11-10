# Assessment expansion: delivery and acceptance gates

This tracks the seven requested gaps. **The platform is not complete across these
areas.** Development includes scoped HTML discovery, four additional fixed
assessment adapters, shared host-local quotas and a versioned owned application
benchmark. None changes the immutable published v1.3.0 release. See
[setup and boundaries](ASSESSMENT_ADAPTERS.md), or run `hunterqa coverage-audit`.

| Priority | Area | Current delivery | Next acceptance gate |
| --- | --- | --- | --- |
| P0 | Website discovery | Bounded HTML and scoped rendered-anchor discovery, ephemeral conventional login and reference-route recall | General SPA actions, complex sessions/SSO and representative route-coverage evaluation |
| P0 | Platform hardening | Supervised fixed workers, per-run controls, shared host-local quotas and optional authenticated local dashboard roles with revocable sessions | Independently verified owner grants, hosted multi-user/tenant isolation, OS sandbox with denied-egress tests, enforced cross-host quotas and distributed workers |
| P0 | Detection effectiveness | Eight versioned owned application cases, retained evidence, source/label hashes and per-class metrics; existing source/header/cookie controls | Externally reviewed ground truth, representative real-world datasets, detection rates across remaining classes and standards coverage |
| P1 | Active vulnerability validation | Fixed SQL canary differential and reflected-HTML Chromium witnesses with owned positive/negative controls | General context-specific validation; blind/OOB SQLi, DOM/stored XSS, SSRF, upload and traversal coverage remain absent |
| P1 | Authentication/authorization | Multi-role/anonymous GET contracts, optional offline signed ID-token verification and owned OIDC/session controls | External SSO, complex sessions, stateful business workflows and general tenant-boundary discovery; status matches alone are insufficient |
| P2 | Infrastructure/network | Exact TCP reachability, verified TLS handshake, bounded SSH identification claims, one expiring UDP DNS question and offline evidence import | Authenticated/general service and OS assessment, broader UDP, isolated AD fixtures and internal attack-path testing |
| P2 | Cloud runtime | Fixed AWS identity/account counters, bounded Azure/GCP resource metadata GETs and selected GCP caller permission-query responses with explicit temporary tokens | Representative sandbox-account validation, complete resource and independently confirmed effective-permission inventory, and broader provider coverage |

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
