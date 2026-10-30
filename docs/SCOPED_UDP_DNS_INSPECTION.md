# Scoped UDP DNS inspection

`udp-dns-inspect` sends one nonrecursive IN A question to one exact numeric DNS
server address and port. It parses a single reply and checks the transaction ID,
opcode and question. For a complete authoritative-flagged NOERROR response with
one direct A RRset, it compares the addresses with an owner-supplied expected set.
Other answer contexts remain unassessed. The AA flag does not authenticate data.

This is an opt-in network command, separate from the TCP workflow adapter and
[TLS inspection](SCOPED_TLS_INSPECTION.md). It does not scan a network or infer
UDP port state.

## Install and prepare

```bash
python -m pip install -e '.[network]'
```

The optional extra supplies `dnspython>=2.9.1,<3` for DNS message construction and
parsing. Core commands do not require it. No DNS resolver API is invoked: the
endpoint must be a numeric address, and no bootstrap name lookup occurs.

Obtain written permission covering the exact server IP, UDP port and question
name, then save this JSON in your private approved directory. Replace the example
addresses, permission reference, expected answer and expiry with reviewed values.
The documentation addresses below are placeholders and are not live targets.

```json
{
  "schema_version": 1,
  "transport": "udp-dns",
  "authorization_reference": "REPLACE_WITH_WRITTEN_PERMISSION_REFERENCE",
  "acknowledged_authorization": true,
  "expires_at": "REPLACE_WITH_TIMEZONE_AWARE_ISO_EXPIRY_WITHIN_24_HOURS",
  "server_ip": "192.0.2.53",
  "server_port": 53,
  "query_name": "canary.owned.example.",
  "expected_ipv4": ["192.0.2.10"],
  "allow_private_network": false
}
```

The contract accepts exactly these fields. Expiry must be in the future and no
more than 24 hours away. The numeric address must be canonical; wildcards,
hostnames, scoped IPv6 addresses and ranges are rejected. Private/loopback
endpoints require `allow_private_network: true`. Unspecified, multicast,
link-local and reserved endpoints remain rejected, except explicitly permitted
loopback. Exact IPv4 or IPv6 endpoints are supported; answers are IPv4 only.

The name is lowercase ASCII with ordinary DNS labels, optionally a final dot.
No wildcard, underscore or IDNA conversion is supported. Supply 1–8 unique
canonical expected IPv4 addresses. They are comparison data, never targets for
connections. There is no DNSSEC validation or secret input.

## Run

```bash
export HUNTERQA_APPROVED_ROOTS=/absolute/private/assessment
hunterqa udp-dns-inspect \
  --input /absolute/private/assessment/dns-contract.json \
  --out /absolute/private/assessment/dns-01.json --authorized
```

On PowerShell, set `$env:HUNTERQA_APPROVED_ROOTS = 'C:\private\assessment'`
and put the command on one line. The destination must be new and its parent must
exist inside approved roots. It is reserved before network activity. Invalid
configuration can leave an empty file; correct the input and choose a new name.

The input is bounded to 16 KiB and fingerprinted. It is checked again immediately
before transmission for expiry and changes. This remains a local operator
attestation; it does not authenticate an owner grant or provide atomic external
revocation. Each invocation reserves one query. Account for repeated invocations
in the written budget; no shared or cross-host quota is applied here.

## Interpret the result

| Field or outcome | Meaning |
| --- | --- |
| `dns-response` | A parseable response matched the transaction and exact question |
| `expected_answer_match: true` | The direct authoritative-flagged A set matched the supplied expectation |
| `expected_answer_match: false` | That comparable A set differed; review the expectation and server configuration |
| `expected_answer_match: null` | No supported complete direct answer was available for comparison |
| `truncated` | A correlated parsed reply set TC; no comparison or TCP fallback occurred |
| `mismatched-response` | ID, opcode, question, QR or echoed RD did not match this operation |
| `invalid-response` | Malformed data or unsupported unsolicited EDNS, TSIG or reserved flag |
| `oversized-response` | The datagram exceeded the 512-byte cap and was not interpreted |
| `timeout`, `refused-or-unreachable`, `unreachable` | No usable DNS response; the UDP port remains unclassified |
| `send-incomplete` | The send operation did not report the complete datagram; no retry |

Refusal, NXDOMAIN, non-authoritative answers, CNAMEs, referrals, empty or mixed
answer sections cannot produce a true or false comparison. A valid direct A
answer can be accompanied by authority/additional records; these are parsed but
not followed or assessed. An error reply without the question is intentionally
not accepted, even where general DNS clients allow it.

The receipt records counts, status, RCODE, the AA flag and hashes. It exports no
server address, queried name, returned addresses, permission reference, raw packet
or private exception text. `datagram_complete` concerns the captured datagram;
the separate `truncated` outcome concerns the DNS TC flag. On oversize replies,
`response_bytes` can be a captured lower bound or unknown on Windows, and no raw
packet digest is claimed. Hashes enable correlation; they do not anonymize
guessable inputs or establish provenance.

`datagrams_sent` counts successful local sends, not delivery proof. A connected
UDP socket filters other source endpoints, but UDP source spoofing and on-path
modification remain possible. AA and AD flags are not cryptographic proof;
`dnssec_verified` and `server_identity_verified` remain false. No automatic
vulnerability finding follows from a mismatch, failure or an available service.
Exit success means a receipt was saved, not that its answer matched.

## Boundaries and validation

There is one send attempt and at most one received datagram, with no retry or
fallback. The combined socket deadline is three seconds, bounded further by
contract expiry. The question has RD=0 and no EDNS. The server may still perform
its own downstream work; coordinate the canary name with its operator. No
recursion/amplification test, ANY/version query, AXFR, update, alias following,
referral following, port/subnet sweep, OS identification, AD or access-path
assessment is implemented.

`tests/test_udp_dns_inspection.py` constructs owned server responses directly
from literal wire fields, separately from the parser. It tests expected/mismatched
answers, denial and truncation, malformed/compression-loop/oversized packets,
transaction/question checks, peer filtering, privacy, expiry, scope and limits.
These are regression controls, not an independent representative accuracy study.

Protocol reference: [RFC 1035, message format and UDP transport](https://www.rfc-editor.org/rfc/rfc1035).
Parser API: [dnspython message construction and parsing](https://dnspython.readthedocs.io/en/stable/message-make.html).
See the [expansion tracker](EXPANSION_PROGRESS.md) for wider unfinished work.
