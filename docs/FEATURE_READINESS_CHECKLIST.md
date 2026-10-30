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
- [x] Selected offline normalized AD/SMB/LDAP policy review
- [ ] OS fingerprinting
- [ ] Broad service/version assessment
- [ ] Live Active Directory assessment
- [ ] Internal attack-path testing
- [ ] UDP

## 5. Cloud runtime — partial

- [x] Optional read-only AWS identity and account-summary adapter
- [x] Selected local configuration/dependency patterns
- [x] Offline normalized AWS/Azure/GCP posture and selected native policy readers
- [ ] Resource and effective-permission inventory
- [ ] Azure/GCP runtime adapters
- [ ] Live cloud infrastructure assessment

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

## Additional Active Directory review pack

- [x] Selected offline account, ACL, certificate, trust and hybrid privilege declarations
- [x] Selected offline domain-controller SMB/LDAP policy review
- [ ] Live directory collection, effective-access calculation and complete AD CS assessment
- [ ] Active attack-path validation and native NetExec execution

See [the AD review guide](ACTIVE_DIRECTORY_REVIEW.md). Supplied declarations remain unverified.

## Additional Wireless review pack

- [x] Selected offline policy checks for all 14 Wireless review contracts
- [x] Seven-directive single-BSS hostapd source reader without executing configuration
- [ ] Live wireless collection, packet analysis and radio validation
- [ ] Comprehensive protocol and device vulnerability assessment

See [the Wireless review guide](WIRELESS_REVIEW.md). Policy declarations and source cues remain unverified.

## Additional Cloud review pack

- [x] Selected offline AWS/Azure/GCP identity, storage, network, audit, federation, permission and compute declarations
- [x] Selected native AWS IAM, GCP IAM and Azure NSG JSON readers
- [ ] Effective IAM/RBAC simulation, inherited policy resolution and actual network reachability
- [ ] Broad runtime cloud inventory, cross-account validation and multi-cloud enforcement assessment

See [the Cloud review guide](CLOUD_REVIEW.md). Native syntax and owner declarations remain unverified.

## Additional Mobile review pack

- [x] Selected offline Android/iOS storage, transport, WebView, authentication, links, IPC and build declarations
- [x] Bounded decoded Android Manifest/Network Security Config and XML iOS Info.plist/entitlements readers
- [ ] Binary APK/IPA analysis, signed-artifact verification and complete platform-default resolution
- [ ] Device/runtime, biometric, storage and mobile-backend vulnerability validation

See [the Mobile review guide](MOBILE_REVIEW.md). Source declarations and actual platform enforcement remain unverified.

## Additional IoT & Embedded review pack

- [x] Selected offline hardware, firmware, boot, updates, MQTT, CoAP, industrial, lifecycle and ecosystem declarations
- [x] Bounded selected Mosquitto ACL syntax and four-flag resolved U-Boot build readers
- [ ] Firmware acquisition/extraction, binary analysis and signed-image/boot-chain verification
- [ ] Hardware, radio, live MQTT/CoAP/ICS and device vulnerability validation

See [the IoT review guide](IOT_EMBEDDED_REVIEW.md). Source cues and owner declarations remain unverified.

## Additional Infrastructure & Red Team review pack

- [x] Seven offline defensive review contracts with nullable control observations
- [x] Selected x86/x64/ARM64 PE header flags and writable/executable section declarations without loading binaries
- [ ] Actual process mitigation, signature, instrumentation and OS/hardware enforcement verification
- [ ] Live infrastructure assessment and representative detection-effectiveness evaluation

See [the Infrastructure review guide](INFRASTRUCTURE_REVIEW.md). No payload, EDR evasion or input capture is executed.

## Additional Exploit Development review pack

- [x] Six offline assurance contracts for memory safety, lab review, crash analysis, mitigations and TOCTOU
- [x] Selected ASan/TSan diagnostic markers and bounded non-loading ELF header review
- [ ] Independent crash reproduction, root-cause validation and demonstrated security impact
- [ ] Runtime mitigation verification and complete exploit-development curriculum/coverage

See [the Exploit Development review guide](EXPLOIT_DEVELOPMENT_REVIEW.md). No exploit, binary or race trigger is executed.

## Additional Fuzzing & Vulnerability Research review pack

- [x] Four offline assurance contracts for campaign, lab, code-review and classification evidence
- [x] Bounded selected AFL++ snapshot metrics and libFuzzer progress/error markers
- [ ] Fuzzer/harness execution, corpus minimization and independent coverage verification
- [ ] Unique vulnerability confirmation, cross-build comparisons and representative detection-rate evaluation

See [the Fuzzing review guide](FUZZING_RESEARCH_REVIEW.md). Metrics and diagnostic markers remain unverified.

## Additional Reconnaissance review pack

- [x] Two offline OSINT assurance contracts with nullable source/methodology observations
- [x] Explicit domain-scope matching, deduplication and bounded name/CT-style JSON imports
- [ ] Live collection, DNS verification, CT/certificate proof validation and independent asset attribution
- [ ] Comprehensive attack-surface discovery and real-world effectiveness evaluation

See [the Reconnaissance guide](RECONNAISSANCE_REVIEW.md). Imported names do not grant active testing permission.

## Additional API Security review pack

- [x] Two offline contracts for API authorization, authentication, resource and business-logic assurance
- [x] Selected OpenAPI 3.0/3.1 JSON security inheritance/alternatives, server and inline request-bound declarations
- [ ] Reference/composed-schema resolution, complete OpenAPI validation and broader format/version support
- [ ] Live BOLA/BFLA, workflow, webhook, rate-limit, gRPC and WebSocket validation

See [the API review guide](API_SECURITY_REVIEW.md). Contract declarations do not prove server enforcement.

## Additional Containers & Kubernetes review pack

- [x] Two offline runtime/workload/cluster assurance contracts
- [x] Selected Docker inspect, Linux-style Kubernetes workload and RBAC declaration readers
- [ ] Effective RBAC, admission/default resolution, image/CVE assessment and isolation verification
- [ ] Live daemon/cluster assessment and demonstrated container-escape validation

See [the Container review guide](CONTAINER_KUBERNETES_REVIEW.md). No workload or cluster operation is executed.

## Additional CI/CD & Pipelines review pack

- [x] Two offline pipeline trust and secret-handling assurance contracts
- [x] Selected GitHub Actions JSON permission, immutable-reference and untrusted-context cues
- [ ] YAML/native Jenkins/GitLab/Azure parsing, expression resolution and complete workflow validation
- [ ] Independent runner isolation, effective grants, environment approvals and OIDC/secret protection verification

See [the CI/CD review guide](CICD_PIPELINES_REVIEW.md). No workflow is executed or secret extracted.

## Additional Cryptography review pack

- [x] Two offline cryptographic-design and TLS assurance contracts
- [x] Selected non-executing Python AST hash, general-random, AES ECB and TLS verification/protocol cues
- [ ] Dataflow, cryptographic correctness, key/nonce lifecycle and side-channel verification
- [ ] Live protocol/cipher enumeration, certificate trust and exploitability verification

See [the Cryptography review guide](CRYPTOGRAPHY_REVIEW.md). Runtime use and real-world effectiveness remain unverified.

## Additional Privilege Escalation review pack

- [x] Two offline Linux/Windows privilege-boundary assurance contracts
- [x] Selected saved getcap declarations and Windows process-service path cues
- [ ] Effective ACL/token/user/namespace resolution, native sudo/setid/task/registry policy analysis
- [ ] Live host enumeration, patch/CVE validation and demonstrated privilege escalation

See [the privilege review guide](PRIVILEGE_ESCALATION_REVIEW.md). No host command or privilege transition is performed.

## Additional Post-Exploitation review pack

- [x] Three offline lateral-movement, persistence and data-exfiltration assurance contracts
- [x] Selected saved Windows task XML and default-format VPC flow v2 review cues
- [ ] Effective task/identity/ACL resolution, traffic direction, asset attribution and telemetry correlation
- [ ] Independent compromise, persistence, lateral-movement or exfiltration validation

See [the post-exploitation review guide](POST_EXPLOITATION_REVIEW.md). No remote action, task execution or data transfer is performed.

## Additional Forensics & C2 review pack

- [x] Two offline evidence-preservation and authorized-framework governance contracts
- [x] Selected Windows audit/time event context and Zeek DNS string/type review cues
- [ ] EVTX/PCAP parsing, timeline correlation, provenance/integrity verification and chain-of-custody proof
- [ ] Independent tampering/C2 attribution and demonstrated real-world detection effectiveness

See [the Forensics & C2 review guide](FORENSICS_C2_REVIEW.md). No evidence alteration, agent deployment or remote tasking is performed.

## Additional Supply Chain review pack

- [x] Two offline artifact/build trust and dependency-confusion assurance contracts
- [x] Selected npm lock integrity/script/source and npmrc/pip source-policy declarations
- [ ] Artifact digest/signature/provenance verification, complete config precedence and dependency resolution
- [ ] Independent namespace ownership, registry trust, package compromise and real-world effectiveness validation

See [the Supply Chain review guide](SUPPLY_CHAIN_REVIEW.md). No package installation, namespace registration or registry access is performed.

## Additional Social Engineering review pack

- [x] Two offline approved-simulation and participant-protection assurance contracts
- [x] Selected saved DMARC declarations and aggregate GoPhish latest-result/config metadata
- [ ] Live DNS/mail authentication, full DMARC policy discovery and receiver enforcement verification
- [ ] Independently verified exercise provenance, human behavior and demonstrated training effectiveness

See [the Social Engineering review guide](SOCIAL_ENGINEERING_REVIEW.md). No message delivery, targeting or credential collection is performed.

## Additional Network review pack

- [x] One offline Layer 2/3 assurance contract with eight ARP/name-resolution/VLAN/DHCP/NAC/IPv6/management/monitoring observations
- [x] Selected saved Linux IPv4/IPv6 sysctl and systemd-resolved declaration readers
- [ ] Runtime all/default/interface/drop-in policy, topology and actual resolver-path verification
- [ ] Independent switch/ARP/DHCP/RA/NAC enforcement and demonstrated network attack resistance

See [the Network review guide](NETWORK_SECURITY_REVIEW.md). No packet injection, interception or host configuration is performed.

## Additional AI Security review pack

- [x] One offline AI application assurance contract with ten prompt/RAG/tool/output/data/model/evaluation observations
- [x] Owned saved-case synthetic canary/tool/retrieval constraints and selected numeric garak JSONL import
- [ ] Live model/provider evaluation, semantic/multimodal detection and actual role/tenant authorization verification
- [ ] Independent detector calibration, model robustness and real-world effectiveness evaluation

See [the AI Security review guide](AI_SECURITY_REVIEW.md). No model, provider, probe, tool or retrieval action is executed.

## Check your installation and owned lab

Use `hunterqa assessment-readiness` for local installation/dependency checks.
Run `assessment-benchmark --out-dir PRIVATE_PATH --authorized`, then
`assessment-readiness --benchmark-dir PRIVATE_PATH --require-owned-lab` to recompute retained evidence.
Real-world effectiveness remains unverified; AWS has synthetic API-contract tests only.
See [the readiness guide](READINESS.md) and [adapter contracts](ASSESSMENT_ADAPTERS.md).
