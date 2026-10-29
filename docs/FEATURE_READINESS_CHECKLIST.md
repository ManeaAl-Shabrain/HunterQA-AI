# HunterQA feature readiness checklist

Checked items are implemented bounded capabilities. Unchecked items remain unfinished.
Every broad area is still partial. A source checkmark is not a live test, production approval or security certification.
These are post-v1.3.0 development capabilities; the immutable release archive is unchanged.

## 1. Website discovery — partial

- [x] Bounded automatic HTML crawling
- [x] Form inventory without submission
- [ ] JavaScript-heavy discovery
- [ ] Session-aware crawling
- [ ] Comprehensive endpoint discovery

## 2. Active vulnerability testing — partial

- [x] Fixed inert-markup baseline/probe comparisons
- [x] Fixed SQL-error baseline/probe comparisons
- [ ] Confirmed SQLi/XSS validators
- [ ] SSRF
- [ ] File upload
- [ ] Traversal
- [ ] Blind/OOB and application-specific validation

## 3. Authentication and authorization — partial

- [x] Dedicated-role and anonymous GET contracts
- [x] Origin-bound per-request credentials and optional body-hash checks
- [ ] SSO negotiation
- [ ] Complex session handling
- [ ] Stateful business logic
- [ ] General tenant-boundary discovery

## 4. Network and infrastructure — partial

- [x] Exact admitted TCP host/port reachability
- [x] Scoped service-evidence import
- [ ] OS fingerprinting
- [ ] Broad service/version assessment
- [ ] Active Directory
- [ ] Internal attack-path testing
- [ ] UDP

## 5. Cloud runtime — partial

- [x] Optional read-only AWS identity and account-summary adapter
- [x] Selected local configuration/dependency patterns
- [ ] Resource and effective-permission inventory
- [ ] Azure/GCP runtime adapters
- [ ] Cloud infrastructure assessment

## 6. Production platform hardening — partial

- [x] Per-run budgets, approvals, deadlines and emergency stop
- [x] Optional shared host-local quota ledger and crash-slot reconciliation
- [x] Opt-in authenticated local dashboard roles and revocable sessions
- [ ] Hosted multi-user deployment and tenant isolation
- [ ] Independently verified owner grants
- [ ] OS sandbox
- [ ] Distributed workers
- [ ] Enforced cross-host organization quotas

## 7. Demonstrated detection effectiveness — partial

- [x] Versioned owned application cases with positive/negative controls
- [x] Retained run evidence, per-class metrics and current-runtime consistency checks
- [ ] Independent real-world evaluation
- [ ] Representative per-class false-negative rates
- [ ] Complete standards coverage

## Additional Web Application review pack

- [x] Ten narrow offline Python source cues with source hashes and remediation
- [x] Six guided review contracts without automated detectors
- [ ] Comprehensive active validation across all 16 skills

See [the category guide](WEB_APPLICATION_REVIEW.md). Source cues remain unverified.

## Additional Auth & Identity review pack

- [x] Offline compact JWT sample comparisons against explicit review policy
- [x] Offline declared OAuth/OIDC web-client configuration checks
- [ ] Cryptographic JWT signature verification and server acceptance tests
- [ ] End-to-end SSO, session and scope-enforcement validation

See [the identity review guide](AUTH_IDENTITY_REVIEW.md). Declarations and decoded claims remain unverified.

## Check your installation and owned lab

Use `hunterqa assessment-readiness` for local installation/dependency checks.
Run `assessment-benchmark --out-dir PRIVATE_PATH --authorized`, then
`assessment-readiness --benchmark-dir PRIVATE_PATH --require-owned-lab` to recompute retained evidence.
Real-world effectiveness remains unverified; AWS has synthetic API-contract tests only.
See [the readiness guide](READINESS.md) and [adapter contracts](ASSESSMENT_ADAPTERS.md).
