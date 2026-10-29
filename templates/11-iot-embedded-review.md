# Private IoT & Embedded review worksheet

Copy this worksheet outside the repository. Never commit filled worksheets,
approvals, device identities, firmware, ACLs, credentials or findings to GitHub.
See [the IoT guide](../docs/IOT_EMBEDDED_REVIEW.md) for the exact input contract.
This is a human review record, not CLI input or proof of authorization.

## 1. Scope and evidence

- Private authorization reference and permitted evidence handling:
- Neutral device/build/case IDs and separate private identity mapping:
- Owner-provided artifacts, provenance and SHA-256 receipts:
- Actual build/device applicability and unknowns:
- Responsible owner for firmware, broker and industrial safety review:

## 2. Independent review

| Area | Applicable evidence and reviewer conclusion | Unknowns / required follow-up |
| --- | --- | --- |
| Hardware and debug interfaces | | |
| Firmware provenance, secret handling and components | | |
| Boot trust anchors and alternate paths | | |
| Update authenticity, rollback and recovery | | |
| MQTT authentication, topic rules and transport | | |
| CoAP peer/resource and transport/object protection | | |
| Industrial segmentation, write authorization and safety | | |
| Credentials, decommissioning and event logging | | |
| Companion/cloud identity and authorization | | |

## 3. Native syntax review

- Selected file and input mode; receipt and report location:
- ACL rule case IDs/line numbers; intended user/global/anonymous scope:
- Broker configuration/plugins/deny precedence not evaluated by the reader:
- Resolved U-Boot build provenance and four selected flags:
- Required signing keys, protected trust anchor and actual boot paths not verified:
- Findings accepted/rejected after independent review, with reasons:

## 4. Remediation and retest

- Owner-approved remediation and maintenance/recovery considerations:
- Fresh evidence/report paths and input hashes:
- Retest result, remaining unknowns and reviewer:

The tool performs no device or industrial operation. Its cues are unverified;
independent runtime, signing, effectiveness and safety claims need separate evidence.
