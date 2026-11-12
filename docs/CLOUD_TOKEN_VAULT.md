# Encrypted Azure and GCP tokens

The shared collector can read a short-lived, explicitly supplied token from the
existing encrypted assessment vault. No login, token refresh, ambient credentials
or provider account is discovered automatically. Existing private token-file
commands remain compatible.

## 1. Prepare private storage

Use a dedicated directory outside Git, assessment inputs and identity-control
files. On Linux:

```bash
install -d -m 700 "$HOME/.local/share/hunterqa-target-secrets"
export HUNTERQA_ASSESSMENT_SECRET_ROOT="$HOME/.local/share/hunterqa-target-secrets"
```

The encrypted document and its separate key must be regular private files owned
by the assessment user. Protect both with mode 0600. Back up keys separately.

## 2. Create a provider-specific vault

Supply JSON through standard input from a trusted local secret-entry tool:

```bash
hunterqa assessment-session-create --purpose azure-token \
  --out "$HUNTERQA_ASSESSMENT_SECRET_ROOT/azure.json" \
  --key-file "$HUNTERQA_ASSESSMENT_SECRET_ROOT/azure.key" --authorized
```

The stdin document uses this structure. Replace the expiry and token locally;
this example is not a usable credential:

```json
{
  "schema_version": 1,
  "expires_at": "REPLACE_WITH_UTC_EXPIRY_WITHIN_24_HOURS",
  "actors": {
    "azure-arm": {
      "origin": "https://management.azure.com",
      "headers": {"Authorization": "REPLACE_WITH_RAW_ACCESS_TOKEN"},
      "cookies": [],
      "local_storage": {}
    }
  }
}
```

Use the raw access token without a `Bearer ` prefix; the fixed collector supplies
the HTTP prefix. Do not put real tokens in shell command arguments, committed
files, screenshots or this example. The vault tool reads stdin until EOF.

For GCP, select `--purpose gcp-token` and supply exactly two actors:

| Actor | Required origin |
| --- | --- |
| `gcp-context` | `https://cloudresourcemanager.googleapis.com` |
| `gcp-assets` | `https://cloudasset.googleapis.com` |

Both actors use the same reviewed token, empty cookies/storage and only the
`Authorization` header. Provider vaults cannot be loaded as web sessions,
directory credentials or AWS signing credentials.

## 3. Collect within an approved scope

```bash
hunterqa assessment-collect --connector azure-inventory --mode LIVE \
  --input /approved/azure-scope.json \
  --session-file "$HUNTERQA_ASSESSMENT_SECRET_ROOT/azure.json" \
  --session-key "$HUNTERQA_ASSESSMENT_SECRET_ROOT/azure.key" \
  --native-out /approved/new-native.json --out /approved/new-shared.json --authorized
```

Use `gcp-inventory` or `gcp-permissions` with the GCP vault and the corresponding
[inventory](SCOPED_GCP_INVENTORY.md) or [permission](SCOPED_GCP_PERMISSIONS.md)
contract. Azure still requires an exact subscription/tenant contract; GCP still
requires an exact project/parent contract. Existing scope, response, timeout,
quota and stop controls apply. Choose either a vault or `--credentials`, not both.

The token is decrypted in memory and reread at each authorization gate. Changing
the vault or key stops further requests, even when the token value is unchanged.
An already in-flight request may finish. No collector stores decrypted tokens in
reports. A local privileged debugger or compromised process can still read memory;
encryption at rest is not OS isolation.

## Verification boundary

Automated tests use synthetic responses to verify origin/purpose isolation,
rotation detection, redaction and existing collector compatibility. Such runs are
labeled DEMO. Default transports use LIVE intent without claiming real provider
validation. Actual Azure/GCP authentication and permission acceptance require the
installation owner's authorized test accounts and have not been performed here.
