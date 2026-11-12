# Operator single sign-on

This guide describes the preserved single-provider compatibility profile.
For new personal deployments use [Local/Google/Entra with Admin MFA](UNIFIED_AUTHENTICATION.md)
and [the localhost walkthrough](PERSONAL_LOCALHOST_SETUP.md).

HunterQA can sign an operator into its dashboard using OIDC Authorization Code
with S256 PKCE. It maps the exact configured issuer and verified subject to an
existing local operator. Local roles and revocation stay authoritative. Email,
group and role claims never create an account or grant a dashboard role.

This signs people into **HunterQA**. It does not automate SSO login to an assessed
customer application or establish target-owner permission. SAML, arbitrary
federation flows and provider-global logout are not implemented.

## Register and configure

Install `.[identity]` and create the private operator/workspace stores first.
Register one code-flow client at the selected provider with S256 support and the
exact callback. Obtain endpoint/issuer values and stable subjects from that
provider's approved administration process. Automatic discovery and email-based
account linking are intentionally absent.

Save this JSON next to the workspace's operator database, outside source and
assessment roots. Use mode 0600 on POSIX and owner-only ACLs on Windows:

```json
{
  "schema_version": 1,
  "issuer": "https://identity.example.test/tenant",
  "client_id": "REPLACE_WITH_REGISTERED_CLIENT_ID",
  "authorization_endpoint": "https://identity.example.test/authorize",
  "token_endpoint": "https://identity.example.test/token",
  "jwks_uri": "https://identity.example.test/keys",
  "redirect_uri": "http://127.0.0.1:8081/oidc/callback",
  "client_secret_file": null,
  "bindings": [{"subject": "REPLACE_WITH_EXACT_PROVIDER_SUBJECT", "username": "viewer"}],
  "local_password_login": false,
  "allow_private_provider": false
}
```

All fields are required. The callback is an exact registered loopback URI for
local mode, or the exact HTTPS origin configured by the authenticated workspace
gateway profile. A hosted profile requires a confidential client: put its secret
in a separate owner-only file in the same control directory and set
`client_secret_file` to its absolute path. Authentication uses `client_secret_post`;
null selects a public PKCE client in local mode. Secrets never enter the browser
authorization URL, cookie or audit record. No refresh token is requested or saved.

Set `oidc_config` in the private workspace configuration. A legacy authenticated
local dashboard can instead set `HUNTERQA_OIDC_CONFIG` alongside its operator
database and persistent secret. Once enabled, removing the OIDC configuration
fails startup rather than silently restoring password login. `local_password_login`
is an explicit local-only fallback; the hosted gateway profile forbids it.

Provider HTTPS endpoints and ports are fixed in the private configuration.
Redirects are not followed. DNS is pinned, certificates/hostnames are verified,
body sizes are bounded and native backchannels share a five-second post-DNS I/O
deadline. Public DNS is required by default. `allow_private_provider: true`
explicitly permits private provider addresses; link-local, unspecified, multicast
and reserved addresses stay rejected. No URI from a token header or callback
selects a backchannel destination.

## Validation and session behavior

Sign-in starts with a CSRF-protected POST. Random state, nonce, PKCE verifier and
browser binding are retained in the private operator database for at most five
minutes. Only one pending browser binding is active in a browser cookie. State is
consumed atomically before token exchange, so failed/replayed callbacks cannot
reuse a grant. Provider errors, duplicate callback values, incorrect response
issuer and mismatched browser binding fail closed without exposing provider text.

ID tokens require an approved RSA key and RS256 signature, exact issuer/audience,
nonce, current integer time claims and supported authorized-party rules. Signing
keys are fetched from the fixed HTTPS JWKS endpoint on each callback, allowing
rotation. Only RSA signature material is used; certificate metadata is not a
trust anchor, and other key types/algorithms are not selected. An advertised
`at_hash` is checked against the returned access token. Hosts need synchronized
clocks; the verifier does not silently apply clock-skew leeway.

Successful verification creates a new local opaque, server-revocable session;
the cookie is rotated and contains no provider token or verifier. Its lifetime
does not exceed the ID token expiry or the eight-hour local maximum. Account
disable/version change and dashboard logout revoke access on the next request.
Logout ends the HunterQA session; it does not terminate the provider's global
SSO session. Removing a binding is a configuration change requiring restart;
disable the local account as well for immediate revocation of existing sessions.

Cookies are HttpOnly, host-only and SameSite=Lax for cross-site GET callbacks;
hosted workspace cookies require Secure. The callback, local CSRF and bounded
sign-in rate checks remain server-side. The dashboard CSP permits form navigation
only to itself and the explicitly configured authorization endpoint.

## Evidence and limits

Owned tests exercise real RSA verification, state/nonce/PKCE, wrong issuer/audience,
unmapped subjects, misleading email/roles, access-token binding, replays, disabled
accounts, configuration removal, native TLS backchannels and a complete Chromium
redirect/cookie/logout flow against a local HTTPS provider. The fixture browser
pins only its owned test certificate; production has no certificate-bypass flag.

These controls are not vendor conformance certification. Real Entra/Google/Keycloak
registration, consent, MFA/conditional-access settings, clock behavior, certificate
rotation, provider outage and the intended TLS deployment need representative
end-to-end verification. Backchannel DNS and complete-process deadlines are not
independently supervised here. Operator/control-directory OS owners remain trusted.

Protocol references: [OIDC code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth),
[OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html).
