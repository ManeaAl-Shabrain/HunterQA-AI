# Auth & Identity — private reviewer worksheet

Copy outside the public checkout. Read [the guide](../docs/AUTH_IDENTITY_REVIEW.md).
This worksheet is a human record, not an authorization grant or executable plan.
Never paste tokens, private keys, secrets or decoded personal data into it.

- Written approval / permitted evidence: `<private reference>`
- Reviewer / UTC date: `<reviewer and date>`
- Neutral case IDs: `<IDs>`
- Approved configuration revision: `<revision>`
- Independent issuer/audience/algorithm policy source: `<private reference>`
- Private evidence/report paths and input SHA-256: `<references>`
- Unavailable evidence / exceptions / review limits: `<record>`

| Skill | Review evidence | State and private evidence reference |
| --- | --- | --- |
| `offensive-jwt` | Token class, approved algorithms, signature verification implementation, trusted key source, issuer/audience, expiration, rotation/revocation and replay/session policy | Not assessed |
| `offensive-oauth` | Actual registered redirects, PKCE enforcement, session/CSRF/replay binding, provider/token validation, scopes, tenants, account linking and SSO lifecycle | Not assessed |

Use **not assessed**, **reviewed with no issue observed**, **candidate**, or
**validated finding**. Only mark a finding validated after independent authorized
reproduction and impact review. Preserve uncertainty; a decoded token or declared
configuration is not proof of the server's behavior.

For each candidate record: rule ID, exact policy/evidence revision, expected and
observed behavior, false-positive analysis, approved validation procedure, impact,
remediation, reviewer decision and fresh retest authorization/results.
