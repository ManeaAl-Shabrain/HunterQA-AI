# Wireless — private reviewer worksheet

Copy outside the public checkout. Read [the guide](../docs/WIRELESS_REVIEW.md).
This worksheet is a human record, not an authorization grant or radio test plan.
Keep actual SSIDs, BSSIDs, MAC addresses, locations, identities and mappings in
separate private records. Do not include passwords, keys, pairing codes, packets
or handshake captures in this worksheet or the normalized JSON template.

- Written permission and selected evidence scope: `<private reference>`
- Reviewer / UTC date: `<reviewer and date>`
- Snapshot collection time and exact configuration/firmware revision: `<private reference>`
- Neutral case IDs and private source mapping: `<reference>`
- Input SHA-256 and private report paths: `<references>`
- Unknown observations, absent devices and applicability exceptions: `<record>`

| Contract | Independent source and applicability review | Decision / evidence |
| --- | --- | --- |
| `offensive-wifi` | Actual security mode, client isolation and management-plane boundaries | Not assessed |
| `offensive-wifi-recon` | Privately mapped inventory, ownership and reviewed band/collection coverage | Not assessed |
| `offensive-wpa2-psk` | Enabled versions/pairwise ciphers and owner-verified credential policy | Not assessed |
| `offensive-wpa3-sae` | Transition/PMF behavior, device/vendor update applicability and exceptions | Not assessed |
| `offensive-wpa-enterprise` | Actual client EAP methods, certificate trust and expected server identities | Not assessed |
| `offensive-wps` | Provisioning need, PIN enablement and effective lockout policy | Not assessed |
| `offensive-evil-twin` | Client auto-join, applicable server binding and rogue-AP detection coverage | Not assessed |
| `offensive-krack-fragattacks` | Exact product/firmware and independent vendor patch applicability | Not assessed |
| `offensive-deauth-disassoc` | PMF scope, client exceptions and remaining denial-of-service exposure | Not assessed |
| `offensive-bluetooth-ble` | Pairing/peer authentication and sensitive GATT access policy | Not assessed |
| `offensive-bluetooth-classic` | Pairing capability, legacy exceptions and negotiated-key policy | Not assessed |
| `offensive-zigbee-thread-matter` | Selected technology/version, authenticated commissioning and key/window policy | Not assessed |
| `offensive-z-wave` | Actual inclusion class, device identity and compatibility | Not assessed |
| `offensive-lorawan-sub-ghz` | Selected technology, activation/counter lifecycle, unique keys and replay defenses | Not assessed |

Use **not assessed**, **reviewed with no issue observed**, **candidate**, or
**validated finding**. Validation requires independent approved evidence and
impact review. A configuration flag is not proof of radio behavior or a named
vulnerability; an empty report does not certify device/network security.

For each candidate retain: rule ID, exact source revision, expected/observed
behavior, false-positive/applicability analysis, independent authorized validation,
impact, remediation, reviewer decision and fresh retest results. This pack never
enables an adapter, transmits frames, captures credentials or executes radio tools.
