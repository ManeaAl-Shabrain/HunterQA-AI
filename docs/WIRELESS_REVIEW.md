# Wireless review pack

**Post-v1.3.0 development capability.** All 14 category names have selected
offline policy checks. This is partial coverage of each skill, not the complete
offensive methodology or a wireless penetration test. No radio or security tool
is accessed. Real-world detection effectiveness remains unverified.

The vocabulary references [Claude-Red's Wireless index](https://github.com/SnailSploit/Claude-Red#wireless).
HunterQA's implementation is original. Upstream prompts, payloads, tools and
installation scripts are not copied, installed or executed.

## Coverage by skill

| Contract | Selected normalized observations | Not delivered here |
| --- | --- | --- |
| `offensive-wifi` | Modern/legacy WPA policy, client isolation, management-plane isolation | Live discovery, security-mode negotiation, segmentation validation |
| `offensive-wifi-recon` | Owner review of inventory, ownership and band coverage | Adapter setup, monitor mode, RF collection or coverage measurement |
| `offensive-wpa2-psk` | Legacy WPA, TKIP pairwise use, owner-verified passphrase policy | Handshake/PMKID collection, key-strength measurement or cracking |
| `offensive-wpa3-sae` | Transition mode, all-station PMF requirement and declared update status | Downgrade, Dragonblood or side-channel testing |
| `offensive-wpa-enterprise` | Client certificate validation, trusted server names and password-based EAP | RADIUS/client authentication, relay or credential collection |
| `offensive-wps` | Enabled/PIN/lockout declarations | PIN requests, guesses or Pixie Dust testing |
| `offensive-evil-twin` | Auto-join, applicable server identity binding, rogue-AP monitoring | Rogue AP, captive portal, phishing or interception |
| `offensive-krack-fragattacks` | Owner-declared applicable patch status | Vulnerability detection, supplicant behavior or packet tests |
| `offensive-deauth-disassoc` | PMF and reviewed legacy-client exceptions | Frame transmission, disconnects or radio denial-of-service validation |
| `offensive-bluetooth-ble` | Secure Connections, authenticated pairing, sensitive GATT authorization | Scanning, GATT enumeration, pairing or MITM testing |
| `offensive-bluetooth-classic` | SSP, legacy pairing and encryption-key policy | SDP, KNOB, BlueBorne or HID validation |
| `offensive-zigbee-thread-matter` | Selected technology, authenticated commissioning, default/shared keys and commissioning window | Protocol decoding, joining, key extraction or injection |
| `offensive-z-wave` | Selected security/inclusion class and identity verification | Inclusion, downgrade, key derivation or hub access |
| `offensive-lorawan-sub-ghz` | Selected technology, LoRaWAN activation/counter validation, unique keys and replay policy | Sniffing, key derivation, replay or sub-GHz transmission |

INFO/WARNING are **unverified triage cues**, not validated impact, CVSS ratings
or certifications. Legacy/transition modes may be intentional. Inventory review,
patch status, credential policy and configuration declarations require independent
source verification. PMF does not prevent every radio denial of service. Server
identity validation must be interpreted in its actual authentication context.

Matter is an application-layer technology with multiple transports; the combined
profile does not assume every Matter device uses an 802.15.4 mesh. Select the
actual technology/version and leave inapplicable or unobserved properties null.
For LoRaWAN, ABP alone is not a vulnerability; lifecycle and counter behavior
matter. No key values are requested or evaluated.

## Mode A — normalized policy evidence

Copy [the JSON template](../templates/HunterQA-wireless-review-template.json) and
[reviewer worksheet](../templates/08-wireless-review.md) to a private case outside
this checkout. Replace only observations supported by approved evidence.

The JSON has exact fields `schema_version: 1` and `records`. Each record requires
`id`, `skill`, and `observations`. IDs must be unique neutral labels matching
`[a-z][a-z0-9-]{0,47}`. The catalog shows every required observation field and its
allowed type/value:

```bash
hunterqa wireless-review-catalog
```

All profile observation fields are nullable. `null` and enum `unknown` mean
unassessed; `false` means an observed false setting. Do not fill true merely to
silence a cue. Patch enums are applied/missing/not-applicable/unknown. Remove
unavailable records; missing skills report `not-assessed`. An untouched template
reports insufficient evidence for all skills, never a security pass.

No names, addresses, locations, passwords, keys, certificates or raw captures
belong in the JSON. Unknown/extra fields and duplicate keys are rejected. Keep
the private identity mapping and original evidence separate. There is no PCAP,
handshake, vendor-export or key-file importer in this mode.

On Kali/Linux with the development checkout installed and environment active:

```bash
mkdir -p "$HOME/hunterqa-cases/wireless"
chmod 700 "$HOME/hunterqa-cases/wireless"
cp templates/HunterQA-wireless-review-template.json "$HOME/hunterqa-cases/wireless/evidence.json"
chmod 600 "$HOME/hunterqa-cases/wireless/evidence.json"
# Edit only the PRIVATE copy using independently reviewed evidence.
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases/wireless"
hunterqa wireless-review \
  --input "$HOME/hunterqa-cases/wireless/evidence.json" \
  --out "$HOME/hunterqa-cases/wireless/review.json" \
  --authorized
```

On Windows, use an access-controlled private directory and the platform's path
separator for multiple approved roots. Input must be an approved regular file.
Output requires an existing approved parent, is private/create-only and never
overwrites existing files. Protect source evidence yourself; input permissions
are not modified by these commands.

## Mode B — narrow hostapd configuration review

Use a private, authorized copy of an existing single-BSS `hostapd.conf`. Do not
upload the file: it can contain real credentials and network identifiers.

```bash
hunterqa wireless-hostapd-review \
  --input "$HOME/hunterqa-cases/wireless/hostapd.conf" \
  --out "$HOME/hunterqa-cases/wireless/hostapd-review.json" \
  --authorized
```

The reader interprets **seven explicit directives** only:

| Directive | Selected interpretation |
| --- | --- |
| `wpa` | Explicit WPA1 and RSN bit declarations; disabling WPA does not establish that a network is open |
| `wpa_key_mgmt` | Selected personal PSK/SAE names for choosing review profiles |
| `wpa_pairwise` | Explicit WPA1 pairwise cipher declarations, only when WPA1 is enabled |
| `rsn_pairwise` | Explicit RSN pairwise cipher declarations, only when RSN is enabled |
| `ieee80211w` | Explicit all-station PMF requirement: 2 required, 1 optional, 0 disabled |
| `wps_state` | Explicit WPS declaration: 0 disabled, 1/2 enabled; PIN/lockout behavior is not inferred |
| `ap_isolate` | Explicit client-isolation declaration, not effective enforcement |

At most five profiles receive source observations: Wi-Fi, WPA2-PSK, WPA3-SAE,
WPS and deauth/disassoc. Other skills remain unassessed. In particular, AP-side
hostapd options do not establish client-side EAP certificate validation, patch
status or passphrase strength. The BSS-wide PMF flag does not prove a bypass of
SAE-specific protections; transition-mode station behavior requires review.

Absent settings remain unknown. RSN cipher defaults are deliberately not
inherited from WPA1 options; group ciphers, driver/runtime defaults, DPP/advanced
key-management variants and vendor-specific behavior are outside this reader.
It accepts only the selected documented option subsets, not every hostapd value.

Duplicate selected directives, `bss=`, `include=` and `rsn_override*` are rejected
because their configuration scope is unsupported. Selected values with inline
comments or unsupported syntax are rejected with contents withheld. Blank and
full-line-comment lines are ignored. Other assignments are counted as unreviewed;
their values are neither evaluated nor exported. Referenced files are never
opened. Secrets/identifiers remain outside the report.

This reader does not validate a configuration as runnable, load hostapd, contact
its control socket, evaluate shell expressions, alter interfaces or access a
radio. A quiet result is not proof of complete or secure configuration.

## Reports, bounds and evidence

Reports retain neutral case IDs, UTC review time, exact input-byte SHA-256,
per-skill states, unknown fields, unverified candidates and remediation. The
hostapd mode also retains line numbers for selected directive names and a count
of unreviewed assignments. It omits actual option values, SSIDs, BSSIDs, MACs,
locations and credentials. Diagnostic text necessarily describes the selected
policy cue. Input hashes and declarations do not prove authenticity or consent.
Native hostapd case IDs include a short input-receipt prefix to distinguish source
snapshots in exported results; these IDs change when the source bytes change.

Input is bounded to 512 KiB. JSON accepts at most 10 records per skill, 140 total.
At most 500 findings are retained; `truncated` and `candidates_not_retained`
expose omitted candidates. Missing/unknown evidence is not a safe default.

Use the existing source-free SARIF exporter without uploading results:

```bash
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/wireless/review.json" \
  --out "$HOME/hunterqa-cases/wireless/review.sarif"
```

There is no radio capture, frame generation, disruption, credential capture,
cracking, replay, pairing, device interaction or external-tool integration in
either mode. These commands are not live workflow adapters. Tests use synthetic
owned declarations/configurations and do not establish real-world detection rates.

## Primary references and next category

- [hostapd project](https://w1.fi/hostapd/) and [hostapd configuration source in AOSP](https://android.googlesource.com/platform/external/wpa_supplicant_8/+/refs/heads/main/hostapd/hostapd.conf)
- [NIST Bluetooth security guide](https://doi.org/10.6028/NIST.SP.800-121r2-upd1)
- [LoRa Alliance security guidance](https://lora-alliance.org/resource_hub/lorawan-security-faq/)
- [Silicon Labs Zigbee commissioning guidance](https://docs.silabs.com/zigbee/latest/using-installation-codes-with-zigbee-devices/) and [Z-Wave security overview](https://www.silabs.com/whitepapers/z-wave-security)

These selected checks do not implement the complete standards or replace
device/vendor applicability review. **Next requested category: Cloud.** It is
not delivered by this pack; the existing bounded AWS account adapter is separate.
