# HunterQA — private Network worksheet

Copy outside this repository. Never commit client configurations, interface names,
addresses, VLAN/network identifiers, credentials or completed evidence records.

1. Record owner authorization, local evidence scope/provenance/date, reviewer,
   actual host/router role and approved topology/policy baseline.
2. Independently review ARP inspection, segmentation/VLAN/trunk controls, DHCP
   snooping, NAC, IPv6 RA guard, management-plane access and monitoring evidence.
3. Review effective all/default/interface sysctl semantics, routing asymmetry,
   namespaces and kernel/runtime state. Saved integers do not establish effective
   settings or exploitability; forwarding can be required for legitimate routers.
4. Review actual name-resolution needs, global/per-link/drop-in settings, systemd
   version, upstream capabilities and application resolver path. Multicast and
   downgrade/opportunistic declarations alone do not prove poisoning or MITM.
5. Fill JSON observations: true = supported assurance review, false = assurance
   gap, null = unassessed. Keep private supporting references here only.
6. Optionally review a saved sysctl subset or resolved configuration. Record
   unknown/reset values, unsupported syntax and duplicate/precedence limits.
7. Independently triage every candidate, document remediation owner and authorized
   retest without applying a blanket host setting. Keep real-world effectiveness unverified.

| Skill topic | Private evidence reference | Unresolved assurance gaps | Remediation owner / retest |
| --- | --- | --- | --- |
| offensive-network-attacks | Fill privately | Fill privately | Fill privately |

Open the [Network guide](../docs/NETWORK_SECURITY_REVIEW.md) from your trusted
checkout if this private copy has moved from its original location.
