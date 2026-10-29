# Auth & Identity review pack

**Post-v1.3.0 development capability.** Both category contracts are implemented
as bounded offline evidence review. Neither is a complete offensive methodology,
a cryptographic verifier, a login client or an SSO assessment.

The names reference [Claude-Red's Auth & Identity category](https://github.com/SnailSploit/Claude-Red#auth--identity).
The implementation is original; upstream agent instructions, tools and payloads
are not installed, copied or executed. Selected review checks are informed by
[JWT BCP / RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) and
[OAuth Security BCP / RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html).
This is not full standards coverage or a compliance certification.

## Coverage

| Skill | Implemented offline comparisons | Still requires independent assessment |
| --- | --- | --- |
| `offensive-jwt` | Compact JWS structure; selected algorithm allowlist; unsigned samples; mixed key-family policy; expiration/temporal ordering; exact expected issuer and expected audience membership; key-source/extension review cues | Signature validity, actual verifier behavior, key confusion, key rotation/revocation, token context, session binding and replay rejection |
| `offensive-oauth` | Declared endpoint/callback HTTPS properties; exact redirect matching; code-flow S256 PKCE; plain PKCE; front-channel access tokens; password grant; state/nonce review cues; public-client credentials grant | Provider discovery, actual redirect enforcement, challenge/verifier binding, CSRF/replay protection, ID-token validation, scope/tenant isolation, account linking and full SSO flows |

JWT expiration is required by this **selected authentication review policy**;
not every application of JWT has identical claim requirements. Choose samples
that fit this context. Expected issuer, audience and algorithm policy must come
from independently approved configuration, not from the sample being evaluated.
Audience-array membership does not assess `azp` or relying-party policy.

An expired sample is an observation, not evidence that a server accepts it.
Neither a missing state flag nor a missing nonce flag alone proves an exploitable
flow: other correctly implemented binding mechanisms can provide protection.
All candidates remain unverified. An empty findings list does not mean "secure".

## Prepare private evidence

1. Obtain permission to inspect the configuration and token samples. Use owned
   lab data where possible. Do not paste production tokens into chat, commands,
   public issues or GitHub.
2. Copy [the JSON template](../templates/HunterQA-identity-review-template.json)
   and [the reviewer worksheet](../templates/06-auth-identity-review.md) into a
   private case directory **outside this checkout**.
3. Replace every placeholder with actual approved evidence. The supplied token
   placeholder intentionally produces an unsupported-sample cue. The false/empty
   security flags are prompts to verify settings, not recommended configuration.
4. Record actual settings; do not change flags merely to silence a finding.
   `pkce_required`, `state_required`, and `nonce_required` describe actual enforced
   policy, not whether a parameter happened to appear in one capture.
5. Remove a sample/client row if that evidence is unavailable. Keep its array
   empty; the report marks the corresponding skill `not-assessed`. At least one
   case is required. Never add client secrets, keys or extra fields to the input.

## Run on Kali/Linux

With the development checkout installed and its environment activated:

```bash
mkdir -p "$HOME/hunterqa-cases/identity"
chmod 700 "$HOME/hunterqa-cases/identity"
cp templates/HunterQA-identity-review-template.json "$HOME/hunterqa-cases/identity/evidence.json"
chmod 600 "$HOME/hunterqa-cases/identity/evidence.json"
# Edit the PRIVATE evidence.json before running the review.
export HUNTERQA_APPROVED_ROOTS="$HOME/hunterqa-cases/identity"
hunterqa identity-review-catalog
hunterqa identity-review \
  --input "$HOME/hunterqa-cases/identity/evidence.json" \
  --out "$HOME/hunterqa-cases/identity/review.json" \
  --authorized
```

On Windows, use an access-controlled private folder and the platform's path
separator for multiple approved roots. The output parent must already exist and
be approved. Reports are private/create-only; choose a fresh filename per run.
Input files are not automatically protected by this command: secure them yourself.
The input and output paths must be distinct; existing files are never overwritten.

The report includes case identifiers, cue/remediation text, UTC review time,
skill assessment states and the SHA-256 of the exact input bytes. It omits token
strings, decoded claim/header values, endpoint URLs and client configuration
values. Use neutral case IDs because those identifiers appear in reports.
The input receipt hash supports local correlation; it is not a signature or proof
of owner consent. Keep the report private as well.

For source-free SARIF export, without uploading it:

```bash
hunterqa report-sarif \
  --file "$HOME/hunterqa-cases/identity/review.json" \
  --out "$HOME/hunterqa-cases/identity/review.sarif"
```

This pack is a standalone local evidence command, not a new live workflow
adapter or dashboard login mechanism. Existing dashboard operator accounts and
dedicated-role access checks remain separate capabilities.

## Input contract and bounds

- Exact schema version 1; unknown fields and duplicate JSON keys are rejected.
- At most 10 JWT samples and 10 OAuth client declarations; unique neutral IDs
  match `[a-z][a-z0-9-]{0,47}` across both arrays.
- Input is at most 256 KiB; each compact token is at most 16,384 characters.
  Only canonical unpadded base64url compact JWS JSON objects are supported.
  JWE, nested token processing, detached/unencoded payloads and custom extensions
  are not validated. A nonempty signature is **not** a verified signature.
- JWT policies select a nonempty subset of HS/RS/ES/PS 256/384/512 or EdDSA.
  Algorithm availability in this list does not make any token verified.
- Temporal comparisons use the recorded UTC review time and zero clock leeway;
  finite numeric dates must lie within the supported magnitude bound of 1e11
  seconds. Provider clock-skew policy is not inferred.
- OAuth declarations cover selected web-client settings. Native/custom-scheme
  and loopback callback exceptions require separate review. HTTPS checks are
  local URL-shape checks, not DNS, certificate, ownership or reachability checks.
- Policy lists are bounded to 20 distinct strings. Supported grants are
  authorization_code, refresh_token, client_credentials, password and implicit.
  Nonredirect service clients may use empty response/redirect arrays; PKCE/state
  checks apply to declared redirect-based/code flows. Device grants and custom
  flows are not supported in this schema.
- No network, key fetching, secret guessing, token signing/mutation/replay,
  provider authentication or state changes occur. No library is added.

## Verification and next category

Synthetic owned fixtures exercise positive/negative JWT/OAuth observations,
redaction, no DNS use, malformed inputs, bounds, explicit authorization, approved
roots, non-overwrite and SARIF context. They do not establish real-world rates,
server acceptance, cryptographic correctness or full SSO security.

**Next requested category: Active Directory.** It has not been delivered by this
pack. Any future addition must distinguish configuration/evidence review from
unimplemented live attack methods.
