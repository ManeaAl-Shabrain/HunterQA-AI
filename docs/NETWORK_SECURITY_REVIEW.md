# HunterQA — Network review

One offline Layer 2/3 assurance contract and selected saved Linux configuration
checks complement the existing bounded connectivity and saved flow review.
This is partial coverage, not a live network pentest or proof of attack resistance.

| Upstream skill ID | Implemented review coverage | Independent evidence still needed |
| --- | --- | --- |
| `offensive-network-attacks` | Eight ARP/name-resolution/VLAN/DHCP/NAC/IPv6/management/monitoring observations; selected sysctl/resolved declarations | Actual host/router role, interfaces, namespaces, switch policy, topology, runtime resolver path and enforcement |

## Start privately

1. Record owner authorization, local evidence scope, provenance, collection date,
   reviewer and the approved network role/topology/policy baseline.
2. Copy [the JSON template](../templates/HunterQA-network-review-template.json)
   and [worksheet](../templates/25-network-review.md) outside this repository.
   Keep actual interface names, addresses, network identifiers and evidence private.
3. Set `HUNTERQA_APPROVED_ROOTS` to the narrow absolute private directory covering
   inputs and output parent. Never commit client configurations or completed worksheets.
4. Set observations to `true` for supported assurance review, `false` for an
   assurance gap, or `null` for unassessed. Keep independent supporting references
   in the private worksheet, not extra JSON fields. Use a fresh output filename.
5. Optionally review a saved configuration or relevant snapshot subset. HunterQA
   never reads `/proc`, enumerates interfaces, resolves names or applies settings.

```text
hunterqa network-review-catalog
hunterqa network-review --input /absolute/private/observations.json --out /absolute/private/review.json --authorized
hunterqa network-config-review --mode sysctl-text --input /absolute/private/network-sysctl.txt --out /absolute/private/sysctl-report.json --authorized
hunterqa network-config-review --mode resolved-conf --input /absolute/private/resolved.conf --out /absolute/private/resolver-report.json --authorized
```

PowerShell: `$env:HUNTERQA_APPROVED_ROOTS = 'C:\Private\HunterQA'`, with Windows
absolute paths. Linux: `export HUNTERQA_APPROVED_ROOTS=/absolute/private`.
Local acknowledgment and input hashes do not independently verify consent,
provenance, current runtime state or topology.

## Selected saved sysctl text

Accepts literal dotted `key=integer` assignments, with full-line `#`/`;` comments.
Whitespace around `=` is supported. Selected keys and review values:

| Declaration | Accepted values | Informational review values |
| --- | --- | --- |
| `net.ipv4.ip_forward` | 0, 1 | 1 |
| `net.ipv4.conf.SCOPE.accept_redirects` | 0, 1 | 1 |
| `net.ipv4.conf.SCOPE.accept_source_route` | 0, 1 | 1 |
| `net.ipv4.conf.SCOPE.send_redirects` | 0, 1 | 1 |
| `net.ipv4.conf.SCOPE.secure_redirects` | 0, 1 | 0 |
| `net.ipv4.conf.SCOPE.rp_filter` | 0, 1, 2 | 0 |
| `net.ipv6.conf.SCOPE.accept_redirects` | 0, 1 | 1 |
| `net.ipv6.conf.SCOPE.accept_ra` | 0, 1, 2 | 2 |
| `net.ipv6.conf.SCOPE.forwarding` | 0, 1 | 1 |

`SCOPE` is `all`, `default` or a simple interface token (ASCII letters, digits,
underscore/hyphen, 1–32 characters). Names are not exported. Dotted interface names,
slash notation, glob keys, ignored-error prefixes, inline comments, includes and
other parameters are unsupported. Unknown assignments are counted; malformed
selected values and duplicate selected keys fail with content-withholding errors.

These are declaration cues, not universal insecure settings or a hardening baseline.
Forwarding can be required on routers, loose source validation can suit asymmetric
routing, and combined `all`/interface/forwarding semantics differ across settings.
No effective value, routing/FIB state, namespace, inheritance or runtime kernel
policy is calculated. IPv6 source-route semantics are deliberately not interpreted
as IPv4 boolean policy; that unsupported parameter is counted, not silently treated
as equivalent. Review the actual role before changing any setting independently.

## Selected saved systemd-resolved INI

Reads exact case-sensitive keys in `[Resolve]`: `LLMNR`, `MulticastDNS`, `DNSSEC`,
`DNSOverTLS`. Boolean forms yes/no, true/false, on/off and 1/0 normalize to yes/no.
Selected additional forms: `resolve` for LLMNR/mDNS, `allow-downgrade` for DNSSEC,
`opportunistic` for DNS-over-TLS. Empty assignments stay unknown/reset; defaults
are not inferred. Duplicate options/sections and nonempty `[DEFAULT]` inheritance
are rejected. Unknown sections/options are counted and their values ignored.

Enabled/resolver-only link-local lookup and disabled/downgrade/opportunistic
validation/transport declarations are informational review cues. Multicast lookup
and compatibility modes can be intentional. No per-link/global combination,
drop-in ordering, distribution/version compatibility, upstream capability,
application resolver path, DNSSEC validation or TLS behavior is verified. Saved
configurations do not prove active poisoning, interception or missing runtime
protection. Repeated-value and full systemd configuration semantics are not emulated.

## Reports, limits and verification

Reports retain SHA-256 input receipts, numbered source-derived cases, selected
public integer/enum settings and coverage counts. Interface names, addresses,
domains, paths and other private configuration values are withheld. Findings are
`INFO`, unverified candidates with context/remediation guidance; conservative SARIF
export omits source locations. Keep even sanitized reports private.

Inputs require explicit authorization and approved-root regular non-symlink files
of at most 1 MiB. Strict normalized JSON rejects duplicate keys, nonfinite numbers,
excessive depth/nodes and malformed contract fields. Bounds: 10 observation records;
text 1,000 lines/4,096 characters per line; 500 retained findings with explicit
truncation counts. Errors withhold contents. Approved roots reduce accidental
access, not hostile concurrent filesystem mutation. No findings is not a security verdict.

No packet injection/capture, ARP/LLMNR/DNS poisoning, MITM, VLAN hopping, DHCP/RA
injection, credential interception, NAC bypass, interface discovery or host changes
are performed. Switch/ARP/DHCP/NAC/RA guard controls use independent owner
observations only, without native device configuration or PCAP parsers.

Owned synthetic tests cover selected values and roles, family/scope distinctions,
resolver modes, unknown/unsupported input, redaction, parser/file bounds,
authorization, no-overwrite, SARIF and absence of process/network execution.
All seven broad readiness areas remain partial; real-world effectiveness remains unverified.

## References and next category

- [Upstream category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/network)
- [Linux IP sysctl](https://docs.kernel.org/networking/ip-sysctl.html)
- [systemd-resolved configuration](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html)

The next pack is [AI Security](AI_SECURITY_REVIEW.md), delivered separately.
