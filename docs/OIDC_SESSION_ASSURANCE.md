# Signed ID tokens and owned OIDC/session assurance

This source addition has two separate capabilities: offline verification of a
saved RS256 ID token, and a fixed owned-loopback OIDC/session HTTP benchmark.
It does not add interactive SSO login, consent automation or a generic external
identity-provider scanner. Historical v1.3.0 assets are unchanged.

## Install

```bash
python -m pip install -e '.[identity]'
```

The optional identity extra uses PyJWT and cryptography for signature operations.
The core installation and the earlier declaration-based `identity-review` retain
their existing behavior. `assessment-readiness` reports this extra separately
without reading token files or contacting an issuer.

## Verify a saved ID token offline

Keep the input and output under an explicitly approved private root, outside the
repository. Supply the public key set and expected policy from independently
approved configuration, not from untrusted token claims or embedded key URLs.
The input envelope has exactly `schema_version`, `token`, `jwks` and `policy`:

```json
{
  "schema_version": 1,
  "token": "REPLACE_WITH_PRIVATE_COMPACT_ID_TOKEN",
  "jwks": {
    "keys": [{
      "kty": "RSA", "kid": "approved-key-id", "alg": "RS256", "use": "sig",
      "n": "REPLACE_WITH_APPROVED_BASE64URL_PUBLIC_RSA_MODULUS", "e": "AQAB"
    }]
  },
  "policy": {
    "schema_version": 1,
    "issuer": "https://issuer.example.test/realm",
    "client_id": "approved-client",
    "expected_nonce": "REPLACE_WITH_ORIGINAL_REQUEST_NONCE",
    "max_lifetime_seconds": 300,
    "max_age_seconds": 300,
    "expected_subject": null,
    "expected_tenant": null,
    "allow_loopback_issuer": false
  }
}
```

This is a shape example; replace placeholders with the actual private sample,
approved public modulus, original nonce and policy. The nonce is 16–128 URL-safe
ASCII characters. Subject and tenant expectations may be `null` when no such
binding is independently known; the report explicitly records whether each was
checked. `expected_tenant`, when set, binds the selected `tenant_id` claim only.
It does not establish resource-side tenant isolation or support every provider's
tenant claim convention.

```bash
hunterqa signed-id-token-verify --input "$CASE/id-token-input.json" \
  --out "$CASE/id-token-verification-001.json"
```

`CASE` must exist under `HUNTERQA_APPROVED_ROOTS`. Use a new output filename each
time. The command performs no network call, key discovery, callback navigation
or server login. Inspect the JSON `accepted` field; creating a report is not
equivalent to accepting a token.

### Supported verification policy

- Hard-coded RS256 verification, with one unique matching `kid` in a supplied
  set of 1–10 public RSA keys. Supported modulus size is 2048–4096 bits with
  exponent 65537. Private keys, encryption keys, signing-only key operations and
  ambiguous IDs are rejected. HMAC/`none` and token-selected algorithms are not used.
- Exact issuer, explicit audience, subject presence, nonce and integer `iat`/`exp`.
  Multi-audience tokens require a matching `azp`; any supplied `azp` must match
  the client. Library signature/registered-claim checks are followed by explicit
  issuer, nonce, maximum lifetime/age and optional subject/tenant checks.
- No clock leeway. `nbf` and `auth_time`, when present, must be strict integer
  dates; not-before is enforced and authentication time cannot follow issuance.
  Noncanonical compact encoding, duplicate JSON keys and non-finite numbers fail.
- The local `max_age_seconds` policy limits token issuance age (`iat`). It is
  not the OIDC authorization-request `max_age` parameter and does not prove
  recent user authentication, MFA strength, `acr` or `amr` requirements.
- Token header key URLs/certificates, critical extensions, compression and
  alternate payload encoding are unsupported and rejected. No token-selected
  URL or key identifier is used as a network or filesystem location.

The result contains hashes and fixed verdict fields, not the token, public key
contents, nonce, issuer name, subject or tenant. `accepted: true` means the
supported signature/claim policy matched **the supplied key anchor**. The tool
does not establish that the key belongs to a real issuer, that a server accepts
the token, that access-token binding/revocation was checked, or that a user is
currently authenticated. It is not a general validator for every JWT/OIDC mode.
Saved-token verification is stateless: it does not consume a nonce or establish
one-time token use. Those lifecycle properties require a real client/session store.

## Owned protocol and session benchmark

```bash
hunterqa oidc-session-benchmark --out-dir "$CASE/oidc-001" --authorized
hunterqa oidc-session-verify --run "$CASE/oidc-001"
```

The benchmark starts one ephemeral service on `127.0.0.1`, generates an RSA key
in memory and uses an original synthetic public client, subject and two tenants.
There is no issuer URL, credential or external target argument. Its fixture
auto-authorizes synthetic requests; it is not an implementation of real user
login or consent. Loopback HTTP is an explicit fixture exception, not permission
to send real tokens over plaintext transport.

The client exercises a code flow with `scope=openid`, S256 PKCE, state and nonce.
It parses the exact registered callback without following it, exchanges a code,
verifies the signed ID token, attempts one code replay and one wrong-verifier
exchange, creates a session with a known fixation seed, reads its own canary,
checks the other tenant's public canary, logs out and retries its own resource.
Requests have fixed local endpoints, bounded bodies and timeouts; no retries,
proxies or native redirect following are used.

| Control | Secure fixture | Deliberately weak fixture |
| --- | --- | --- |
| Exact callback/state, ID-token signature and nonce | Client rejects mismatches | Same correctly validating reference client |
| PKCE verifier | Wrong verifier rejected | Wrong verifier accepted |
| Code replay | Consumed code rejected | Consumed code accepted again |
| Session fixation | Session ID replaced | Supplied seed reused |
| Tenant boundary | Other tenant denied after own access succeeds | Other public tenant canary returned |
| Logout | Retained session rejected after logout | Retained session still accesses its own canary |

There are 18 labelled observations across both variants and 22 fixed HTTP
operations. Labels are declared separately in `fixtures/oidc-session-v1.json`.
Five deliberately faulty guards are positive issue cases. Per-class confusion
counts, inconclusive counts and miss/rate metrics describe this small fixture
only. `positive_miss_rate` includes inconclusive positives; classes with no
positive examples report no recall value rather than a perfect rate.

Keep `ground-truth.json`, `secure.json`, `weak.json` and `benchmark.json` together.
Receipts contain endpoint names, response statuses, lengths, hashes and fixed
witnesses. No private RSA key, ID/access token, code, verifier, nonce, session
cookie or user claims are saved. Offline verification checks current source and
package identity, receipt structure/bindings and recomputed metrics. It does
**not** replay HTTP or reverify discarded tokens. Re-run into a new directory for
fresh protocol/session evidence. A directory owner can forge local artifacts;
these are consistency records, not a signed independent audit.

## Coverage references and gaps

The bounded policies reference [OpenID Connect Core ID-token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation),
[RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636), and the
[PyJWT verification API](https://pyjwt.readthedocs.io/en/stable/api.html).
This is an implementation map, not full standards coverage or certification.

External provider discovery/JWKS rotation, interactive SSO, consent, MFA,
federation, account linking, refresh/logout federation, production cookie/TLS
policy, representative business workflows and general tenant-boundary discovery
remain unverified or unimplemented. A signature or a fixture guard does not
establish those properties. See [expansion progress](EXPANSION_PROGRESS.md).
