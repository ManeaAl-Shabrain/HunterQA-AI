# Native cloud transport deadlines

Azure resource inventory, GCP resource inventory and GCP permission checks now
share one five-second I/O deadline for each native HTTPS request after DNS.
Previously each socket operation could wait five seconds again: a peer sending
small amounts regularly could extend status/header/body collection far beyond
that time. Regular incoming bytes no longer restart this budget.

No new flag, dependency, endpoint override, retry or credential mechanism is
introduced. Resource/permission scope, certificate and hostname verification,
public DNS admission, response size limits, pacing and shared quotas remain in
force. Existing workflow, bounty, AWS and custom Python transports are outside
this change.

## What is timed

The monotonic deadline starts immediately before TCP connection, after DNS,
local trust-context setup and an additional authorization check. Admission is
checked both after DNS and after trust setup so local setup delays cannot extend
permission for a new TCP connection. TCP consumes
the same budget as the TLS handshake and all subsequent request writes and
response reads. Authorization/quota rechecks after TLS consume the remaining
time; if none remains, bearer headers cannot be sent.

Before TLS, each network write and every underlying response read, the socket
timeout is reduced to the time remaining. An expired budget raises a generic
timeout, with no endpoint or token in the message. The response reader applies
the guard below HTTP buffering, including:

- status-line and header parsing;
- fixed-length and EOF-delimited response bodies;
- chunk-size lines, chunk data and final trailers.

The standard HTTP parser and existing encoding/body-size checks remain in use.
Normal Content-Length, chunked, close-delimited and keep-alive replies still
work. Explicit response-reader cleanup runs on success, oversized/compressed
responses, read errors and interruption. A response can finish reading after
HTTPConnection has logically closed its connection; the TLS channel is released
when both the connection and its last response reader close. See the Python
[socket timeout and file-lifetime documentation](https://docs.python.org/3.11/library/socket.html).

## Results and recovery

These commands continue to report native transport timeouts as
`outcome: transport-rejected`. They do not retry or switch transport. Completed
earlier context/pages remain available. Failed inventory remains incomplete;
failed permission queries retain null permission values, never false denials.
No new finding or vulnerability is inferred from a timeout.

Each next API request gets a new five-second budget, not the unused time from the
previous request. Existing upfront [shared quota reservations](NATIVE_SHARED_QUOTAS.md)
remain fully charged on admitted failure. The active slot is released separately
and cleanup status remains in the receipt. A timeout does not justify refunding
units, increasing scope or automatically reconciling a still-running process.

## Limits

This is a per-request native I/O control, not an independently supervised process
deadline or cancellation service. OS DNS lookup remains outside the budget and
has no portable deadline here. Trust-context setup, local files/database work
before connection, pacing between calls, JSON processing and report creation are
not independently time-limited by it. OS scheduling can delay timeout handling;
already buffered data can be processed without new network reads. The code does
not preempt CPU work, kill a process or atomically revoke in-flight requests.

Caller-supplied Python transports remain trusted code and do not inherit this
socket wrapper. Hosted tenant/OS isolation, distributed workers, cross-host quota
and independently verified owner permission remain unfinished. Passing owned
slow-peer tests does not establish representative Azure/GCP field performance.

## Owned verification

Controls exercise real TLS-verified local peers with a reduced private test
budget, emitting data regularly inside the old inactivity timeout. They cover
status, headers, body, chunk-size, chunk-data and trailer delays for Azure GET,
GCP GET and GCP permission POST. Normal response framing and explicit TLS-channel
release are checked too. Clock-driven controls separately verify that connection,
handshake and a late post-TLS authorization check cannot reset the deadline or
transmit bearer data after expiry.

Full-command controls retain matched project/subscription context when a later
response times out, keep permission values unknown, preserve the full quota
charge and release the active slot. No real cloud account or external target is
contacted by these controls.
