# HunterQA — Cryptography review

Two offline assurance contracts and selected Python source checks help organize
cryptographic-design and TLS review. This is partial coverage: no proof of
cryptographic correctness, exploitable weakness, safe TLS or standards compliance.

| Skill | Automated / structured coverage | Independent evidence still needed |
| --- | --- | --- |
| `offensive-crypto-attacks` | Owner observations; selected MD5/SHA-1, general-purpose random and AES ECB calls | Actual security use, authenticated encryption, key lifecycle, nonce uniqueness, KDF and side-channel properties |
| `offensive-tls-attacks` | Owner observations; selected unverified TLS context, explicit HTTP verification disablement and legacy-only context calls | Live protocols/ciphers, chain/hostname/revocation behavior, patch status, replay policy and mTLS identity |

## Start privately

1. Obtain owner authorization for the local source/evidence review and record its
   scope. Operator acknowledgment does not independently verify owner consent.
2. Copy [the JSON template](../templates/HunterQA-crypto-review-template.json) and
   [worksheet](../templates/19-cryptography-review.md) outside this repository.
   Never provide keys, passwords, plaintext, ciphertext samples or token values.
3. Set `HUNTERQA_APPROVED_ROOTS` to the absolute private directory holding the
   inputs and output parent. Use a narrow directory, not an entire disk.
4. Set each observation to `true` only for a supported assurance review, `false`
   for a declared assurance gap, or `null` for unassessed. Retain independent
   supporting evidence references privately in the worksheet.
5. Use a fresh report filename; reports never overwrite existing files.

```text
hunterqa crypto-review-catalog
hunterqa crypto-review --input /absolute/private/observations.json --out /absolute/private/observations-report.json --authorized
hunterqa crypto-source-review --input /absolute/private/application.py --out /absolute/private/source-report.json --authorized
```

PowerShell example: `$env:HUNTERQA_APPROVED_ROOTS = 'C:\Private\HunterQA'`.
Use Windows absolute input/output paths. Linux example:
`export HUNTERQA_APPROVED_ROOTS=/absolute/private`.

## Selected Python AST patterns

Source is parsed, never imported or executed. Referenced dependencies and other
files are not opened. Recognized calls use unambiguous top-level imports, including
aliases and `from` imports. Names rebound anywhere in the file or shadowed by
parameters, declarations, exception/match bindings or additional imports are
conservatively skipped. Star imports disable imported-name resolution.

| Pattern | Review candidate |
| --- | --- |
| `hashlib.md5`, `hashlib.sha1`, selected literal `hashlib.new` names | Determine whether collision resistance or authentication matters |
| Selected `random` output calls | Determine whether the output is security-sensitive; simulation/sampling is often legitimate |
| `Crypto` / `Cryptodome` AES constructors with a directly resolved `MODE_ECB` | Review the encryption design and authenticated-encryption requirements |
| `ssl._create_unverified_context` | Review actual client trust and endpoint identity validation |
| Selected direct `requests` / `httpx` calls with literal `verify=False` | Review whether verification is intentionally disabled and restore appropriate trust |
| `ssl.SSLContext` with selected explicit legacy protocol constants | Review migration to a maintained modern TLS policy |

No dataflow, reachability, type inference, local import resolution, dynamic
imports, wrapper/session tracking or constant propagation is implemented.
Monkey-patched attributes, indirect aliases, numeric mode constants, assigned
protocol minima and custom libraries can be missed. Code may be unreachable or
unused. No finding is a security verdict; weak hashes or general-purpose random
calls can have legitimate non-security purposes. No findings is not proof of safety.

## Reports and limits

Findings are `INFO`, unverified review candidates with generic remediation
recommendations. The report contains a SHA-256 receipt of the original input
bytes and receipt-derived case IDs. Source paths, names, excerpts, literal values,
keys and ciphertext are not exported. Source coordinates in case IDs distinguish
candidates; precise source locations are deliberately omitted from SARIF exports.
Even sanitized reports should remain private.

Inputs require explicit authorization, an approved root and a regular non-symlink
file of at most 1 MiB. Normalized JSON rejects duplicate keys, nonfinite numbers,
excessive depth/nodes and unexpected contract fields. Contracts permit 10 records
per skill, 20 total. Python AST limits: 50,000 nodes and depth 100; at most 500
findings are retained, with explicit truncation counts. Malformed input fails
with errors that withhold its contents. Private-file approval reduces accidental
access; it is not protection against a hostile concurrent filesystem writer.

No live handshake, scanner invocation, certificate parsing, cipher enumeration,
key recovery, cracking, padding oracle, plaintext recovery, pinning bypass,
Heartbleed or other CVE validation is performed. TLS 0-RTT/mTLS/revocation, key/KDF
parameters and nonce/replay correctness use independent review observations only.

Tests use owned synthetic sources and observations. They check pattern matches,
alias/shadow exclusions, privacy, authorization, parser limits, report bounds and
absence of network/process execution. Real-world effectiveness remains unverified.

## References and next category

- [Upstream Cryptography category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/crypto)
- [Python hashlib warnings](https://docs.python.org/3/library/hashlib.html)
- [Python random security warning](https://docs.python.org/3/library/random.html)
- [Python SSL contexts](https://docs.python.org/3/library/ssl.html)
- [RFC 8996: deprecated TLS versions](https://www.rfc-editor.org/rfc/rfc8996.html)

**Next requested category: Privilege Escalation.** It is not delivered by this pack.
