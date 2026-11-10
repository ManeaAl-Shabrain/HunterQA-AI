# Scoped SSH identification

`ssh-service-inspect` connects once to one explicitly approved numeric TCP
endpoint and observes its server-first identification line. It sends no client
identification, credentials or application data. This is a bounded service cue,
not a complete SSH client, authenticated fingerprint or vulnerability scanner.
The core install is sufficient; no SSH library or external executable is used.

## Prepare and run

Obtain written permission for the exact IP, TCP port and connection budget. Save
this contract in a private approved directory, replacing the documentation-only
address, permission reference and expiry. The example is not a live target.

```json
{
  "schema_version": 1,
  "transport": "tcp-ssh-identification",
  "authorization_reference": "REPLACE_WITH_WRITTEN_PERMISSION_REFERENCE",
  "acknowledged_authorization": true,
  "expires_at": "REPLACE_WITH_TIMEZONE_AWARE_ISO_EXPIRY_WITHIN_24_HOURS",
  "server_ip": "192.0.2.22",
  "server_port": 22,
  "allow_private_network": false
}
```

Exactly these fields are accepted. The contract is capped at 16 KiB. The address
must be canonical IPv4 or IPv6; hostnames, ranges, zone IDs, wildcards and alternate
spellings are rejected. Private/non-global addresses require explicit opt-in.
Unspecified, multicast, link-local and reserved addresses are rejected, except
explicitly permitted loopback. Expiry must be in the future within 24 hours.

```bash
export HUNTERQA_APPROVED_ROOTS=/absolute/private/assessment
hunterqa ssh-service-inspect \
  --input /absolute/private/assessment/ssh-contract.json \
  --out /absolute/private/assessment/ssh-01.json --authorized
```

On PowerShell, set `$env:HUNTERQA_APPROVED_ROOTS = 'C:\private\assessment'`
and run the command on one line. The output must be new, inside an existing
approved parent directory. It is reserved before network activity; an input error
can leave an empty file. Correct the input and select a new output filename.

## Bounds and interpretation

One connection and a combined five-second TCP/read deadline are allowed, capped
by contract expiry. Each read also checks the unchanged contract, its expiry and
the optional shared quota. There is no DNS lookup, proxy, retry, authentication,
forwarding, host-key collection, key exchange or algorithm enumeration. An OS
connection still sends TCP control packets; zero application bytes does not mean
zero network traffic. A server that waits for a client greeting can time out.

At most 2048 bytes are read in chunks of at most 256 bytes. At most ten lines
before identification are accepted; the eleventh produces a limit outcome.
Each complete line must use CRLF and fit within 255 bytes including CRLF.
Pre-identification content is discarded. The SSH line uses a strict printable
ASCII subset of [RFC 4253 section 4.2](https://www.rfc-editor.org/rfc/rfc4253.html#section-4.2).
Bare-LF legacy greetings and non-ASCII comments are deliberately unsupported;
rejection is not a standards-compliance finding or proof the port is not SSH.

| Outcome or field | Meaning |
| --- | --- |
| `identification-observed` | A bounded supported identification line was received |
| `advertised_protocol` | Self-declared `2.0`, compatibility `1.99`, or legacy `1.5`/`1.3`; no negotiation occurred |
| `advertised_product_hint` | Exact case-sensitive prefix cue for OpenSSH, Dropbear or libssh, otherwise null |
| `software_sha256`, `identification_sha256` | Fingerprints of the advertised software token and identification line; raw values are withheld |
| `unsupported-protocol` | A syntactically accepted line advertised another protocol string; raw string withheld |
| `invalid-identification`, `line-limit`, `byte-limit`, `pre-identification-limit` | The supported parser or collection bounds were exceeded |
| `closed-before-identification` | The peer closed without a complete accepted identification |
| `timeout`, `refused`, `unreachable` | Transport observation only; no SSH or vulnerability conclusion |
| `contract-stopped`, `quota-stopped` | A subsequent operation was denied by the local contract or shared ledger |

Product/protocol claims can be forged. The command does not publish raw software
versions, comments, preambles, endpoint addresses or exception messages, and does
not map banners to CVEs. `server_identity_verified`, `service_product_verified`
and `vulnerability_verified` remain false; findings remain empty. A hash is not
proof of evidence provenance, confidentiality or independently verified consent.
Bytes received alongside identification may include a prefix of key exchange;
they count against the byte cap but are not interpreted or retained.

With `HUNTERQA_QUOTA_LEDGER`, one operation and active slot are reserved before
transport. The full unit remains charged on all admitted outcomes; only the slot
is released. The receipt records cleanup status. See [shared quota operation and
recovery](NATIVE_SHARED_QUOTAS.md), including manual reconciliation after cleanup
failure. This is cooperative enforcement on one trusted host, not tenant or OS
isolation or cross-host enforcement. Checks cannot atomically revoke a read
already in progress; completed observations can remain in the report after stop.
The local contract remains an operator attestation.

Owned tests cover real IPv4/available IPv6 loopback peers with no received client
application data, fragmented and coalesced input, malformed/oversized streams,
deadline and contract changes, transport failures, create-only output and quota
conservation. They do not establish independent field accuracy, full service/OS
identification or an authenticated SSH security assessment.
