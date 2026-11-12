# Scoped read-only Active Directory collection

The LDAPS connector collects selected actual directory attributes into a private,
pseudonymized snapshot. It reuses existing AD account-flag rules and adds explicit
domain password-length and lockout-policy review against an approved baseline.
It inventories selected account, group, trust and GPO metadata; it does not read
GPO contents, resolve effective DACLs, assess all AD CS conditions or execute
privilege paths.

## 1. Prepare a reader and private credentials

Install `python -m pip install -e '.[directory,identity]'`, or use the shared
Linux runtime, which includes both extras. Use a dedicated ordinary directory
reader with only the rights needed to read the selected naming context and
attributes. Do not supply a domain administrator. Environments that deny these
reads return incomplete evidence; the connector does not request more rights.

Create a dedicated assessment vault using the existing
[private session mechanism](SCENARIO_ASSESSMENTS.md). Its only actor must be
`directory`, with origin `https://dc.example.test:636`, empty cookies/storage and
exactly two headers: `X-LDAP-Bind-DN` and `Authorization`. For this connector only,
these hold the reader's distinguished name and password. They are encrypted at
rest, never sent as HTTP, never included in reports and never accepted inline as
CLI arguments. Supply real values privately through stdin; do not put them in
chat, Git, shell history or the public contract. The reader DN must be under the
exact authorized domain base. Vault authorization expires within 24 hours.

## 2. Review the contract

Save this schema illustration under an approved assessment root, replacing the
example values and expiry. It is not a live target recommendation:

```json
{
  "schema_version": 1,
  "authorization_reference": "Owner's written directory read permission",
  "acknowledged_authorization": true,
  "expires_at": "REPLACE_WITH_UTC_EXPIRY_WITHIN_24_HOURS",
  "mode": "LAB",
  "server_ip": "127.0.0.1",
  "server_port": 636,
  "tls_server_name": "dc.example.test",
  "base_dn": "DC=example,DC=test",
  "allow_private_network": true,
  "ca_file": "/absolute/approved/lab-ca.pem",
  "max_pages": 2,
  "page_size": 50,
  "timeout_seconds": 30,
  "minimum_password_length": 14
}
```

Only an exact numeric endpoint is contacted. LAB rejects global addresses.
TLS uses system trust or the reviewed CA file, hostname validation and TLS 1.2
minimum. There is no plaintext/StartTLS fallback, certificate bypass, referral,
alias dereference, schema query, automatic ranged-membership expansion or retry.
The RootDSE naming context must match the declared domain base before subtree
collection. Filters and attribute names are fixed in code; no passwords, hashes,
tickets or security descriptors are requested.

```bash
hunterqa ad-directory-preflight --input /absolute/contract.json \
  --session-file /private/directory.json --session-key /private/directory.key

hunterqa ad-directory-collect --input /absolute/contract.json \
  --session-file /private/directory.json --session-key /private/directory.key \
  --approval REVIEWED_SHA256 --snapshot-out /absolute/new-snapshot.json \
  --out /absolute/new-report.json --authorized
```

Both outputs must be new approved paths. Add workspace/project options as in
the shared mode guide to register the report in existing history. The optional
shared quota ledger reserves the worst-case operations. A `stop` file beside the
contract stops further work; configuration/key/CA changes and expiry invalidate
approval. Closing a connection after stop does not issue another LDAP operation.
Collection is bounded by five pages, 100 entries per page, a 60-second total
deadline and 1 MB of received application data. Truncation/errors remain explicit.

## 3. Interpret the output

Snapshots retain selected numeric attributes, classes and hashed identities/
relationships, not raw DNs or credentials. Reports retain origin, hash references,
collection completeness and sanitized error type. A received attribute is a
server assertion, not independent proof of effective access.

Fine-grained password policies can override domain defaults. `adminCount` may be
historical and does not establish current administrative access. At most 200
accounts pass through the legacy account-rule evaluator; additional collected
accounts are explicitly counted as omitted. Group primary membership and ranged
values are not resolved. Missing attributes and omitted objects are not secure
defaults. Imported snapshots can be reviewed through `assessment-review --module
ad --mode LAB` or LIVE without reconnecting.

## 4. Repeatable actual Samba laboratory

The disposable lab builds a Samba AD directory, creates a normal reader, sets
explicit synthetic domain policies and runs the connector as OS UID 10001. The
server needs root inside its container for provision and service ports; the
assessment client does not. No personal accounts or host directories are used.

```bash
docker build -f labs/active-directory/Dockerfile -t hunterqa-owned-ad .
docker run --rm --network none --hostname dc.owned.lab.test \
  --pids-limit 128 --memory 1g --cpus 2 --security-opt no-new-privileges:true \
  -e HUNTERQA_OWNED_AD_TEST=1 hunterqa-owned-ad
```

Build dependencies need connectivity initially. The test execution has no
network interface beyond loopback, no host mounts and no published ports.
The public passwords in the fixture are for this disposable directory only.
The lab uses `user.NTACL` to avoid granting SYS_ADMIN: this is a test-only storage
choice, not a production ACL recommendation. Samba documents that this namespace
can be modified through local access, so no ACL-security validation claim is made.
[Samba ACL documentation](https://www.samba.org/samba/docs/current/man-html/vfs_acl_xattr.8.html)
explains that behavior. The collector disables ldap3's automatic referral and
range handling; see the [connection documentation](https://ldap3.readthedocs.io/en/latest/connection.html).

Mock connector tests and actual TLS tests are separate from this Samba job.
An actual Samba pass validates only the selected LDAP behavior in that lab,
not Microsoft enterprise AD, complete directory permissions or real cloud
providers. Consult the current validation report and CI result before claiming
the Samba laboratory has passed.
