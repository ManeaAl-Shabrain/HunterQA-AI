# HunterQA — private Cryptography worksheet

Copy outside this repository. Do not commit completed copies, source code,
credentials, keys, tokens, plaintext, ciphertext or client identifiers.

1. Record the private owner authorization reference, source/evidence scope,
   reviewer, review date and applicable threat model.
2. Inventory cryptographic purposes. Distinguish security-sensitive hashing and
   randomness from checksums, sampling and simulation. Review the actual design.
3. Review algorithm/mode selection, integrity protection, key generation/storage/
   rotation/revocation, nonce uniqueness, password KDF parameters and side channels.
4. Review TLS protocol/cipher policy and patch evidence independently. Verify
   actual certificate chain, hostname and revocation behavior where authorized.
   Review mTLS identity, TLS 0-RTT/replay and trust restrictions separately.
5. Fill the JSON observations: true = supported review, false = assurance gap,
   null = unassessed. Keep private evidence references here, not in JSON fields.
6. Optionally run the selected Python source reviewer. Treat every candidate as
   informational until its use, reachability and impact are independently verified.
7. Record remediation, owner and retest evidence. Do not claim full cryptographic
   correctness or real-world effectiveness from synthetic tests or a clean report.

| Skill | Private evidence reference | Unresolved assurance gaps | Remediation owner / retest |
| --- | --- | --- | --- |
| offensive-crypto-attacks | Fill privately | Fill privately | Fill privately |
| offensive-tls-attacks | Fill privately | Fill privately | Fill privately |

Open the [Cryptography guide](../docs/CRYPTOGRAPHY_REVIEW.md) from your trusted
checkout if this private copy has moved away from its original location.
