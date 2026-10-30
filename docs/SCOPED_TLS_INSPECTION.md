# Scoped TLS inspection

`tls-service-inspect` opens one TLS connection to an explicitly permitted HTTPS
host and port. It checks the certificate chain, validity and hostname against
the current client's trust policy. It records the negotiated TLS version,
cipher, ALPN and a SHA-256 fingerprint of the leaf certificate. It sends no HTTP
request. This is separate from the existing TCP-only `service-enumeration`
workflow adapter.

## Run

Use a private approved directory and an owner-reviewed scope profile, as in the
[assessment guide](AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md). The profile must
admit the exact host, port and root path `/`, with HEAD or GET permitted and at
least one request in its budget. A permission restricted to `/app` does not
authorize this host-level inspection. Written permission must cover TLS
inspection; the URL profile and acknowledgement cannot establish ownership.

```bash
export HUNTERQA_APPROVED_ROOTS=/absolute/private/assessment
hunterqa tls-service-inspect \
  --profile /absolute/private/assessment/scope.json \
  --target https://owned.example.test:443/ \
  --out /absolute/private/assessment/tls-01.json --authorized
```

On PowerShell, set the variable using
`$env:HUNTERQA_APPROVED_ROOTS = 'C:\private\assessment'` and put the command on
one line. Use the installed `hunterqa` executable from your active environment.

For a private PKI, add `--ca-file /absolute/private/assessment/public-ca.pem`.
This bounded local PEM certificate bundle **replaces** platform trust roots for
the connection. It must be inside approved roots and contain no private key.
The report records its hash, not its contents. Trusting a supplied CA does not
authenticate who supplied it. No optional package is required for this command.

The destination must be new and its parent must already exist inside approved
roots. It is reserved before any connection; a configuration error can leave an
empty file. Keep it and choose a new filename after correcting the input.

## Interpret the receipt

| Outcome | Meaning |
| --- | --- |
| `verified` | This handshake satisfied certificate/name/time validation and the selected trust policy |
| `certificate-rejected` | Certificate verification failed; a numeric OpenSSL verification code is retained |
| `tls-error` | TLS failed without a completed certificate verdict, including some non-TLS services |
| `refused`, `timeout`, `unreachable` | A transport/handshake failure; certificate status remains unknown |

`certificate_and_hostname_verified` is true only on success, false on explicit
certificate rejection, and null for inconclusive transport/TLS errors. A rejected
certificate produces no automatic vulnerability finding. A private CA absent
from local trust, local time or client policy can explain rejection.

Names, addresses, certificate subject/SAN fields, raw certificates, exception
messages and session secrets are withheld. The target and scope are bound by
hashes. A receipt is a local observation, not independent provenance or a
cryptographic attestation. Exit success means a receipt was saved; read
`outcome` to decide whether verification succeeded.

## Bounds and remaining work

All DNS answers pass the existing scope address checks before one numeric address
is dialled; the original hostname remains the verification/SNI name. There are no
proxy requests, retries, redirects, insecure fallback or client certificates.
The combined TCP/handshake budget is five seconds after DNS. OS DNS resolution
has no portable deadline. Private addresses require the existing explicit
`lab_mode` and `allow_private_network` profile settings; unsafe/reserved address
classes remain rejected. The profile's path exclusions are still enforced.

TLS 1.2 is the minimum offered version. Strict X.509 verification and trusted
partial chains are enabled; an explicitly trusted intermediate can be a trust
anchor. Default platform roots and OpenSSL policies differ across installations.
The command does not enumerate supported protocols/ciphers, retrieve OCSP/CRLs,
verify revocation, identify an HTTP product, fingerprint an OS or assess UDP,
AD or access paths. ALPN is negotiation metadata, not proof of an application
product. A successful handshake does not establish general service security.

Each invocation admits at most one connection. There is no persistent approval,
cross-invocation budget or shared quota integration. Use this command separately
from workflow runs and account for its connection in the written assessment
budget. `SSLKEYLOGFILE` is not applied to this connection.

## Validation

`tests/test_tls_inspection.py` uses an owned IPv4 server with a controlled local
DNS answer. It exercises a trusted valid certificate, an unknown CA, an expired
certificate, a hostname mismatch and a plaintext endpoint. Additional controls
check pre-network scope/CA/output rejection, numeric pinning with the original
hostname, deadlines, failure privacy and key-log suppression. These tests are
regressions, not an independent real-world effectiveness benchmark.

Implementation semantics follow the Python [`ssl` API](https://docs.python.org/3.11/library/ssl.html).
The [expansion tracker](EXPANSION_PROGRESS.md) lists the wider remaining work.
