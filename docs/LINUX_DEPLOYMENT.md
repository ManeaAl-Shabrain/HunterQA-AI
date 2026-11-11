# Shared Linux deployment profile

This first deployment stage uses one application, one dependency/tool manifest
and one private workspace layout for Docker Compose and native systemd. It does
not complete the [accepted authentication/MFA requirements](ACCEPTED_PLATFORM_REQUIREMENTS.md).
The current application still supports local accounts or one explicitly bound
OIDC provider. Simultaneous Google/Entra selection and enforced administrator MFA
remain open. Do not treat this profile as production acceptance.

The initial profile targets Debian 12 / Ubuntu 24.04 and Linux containers.
Install Python 3.11+ for rendering the non-secret specification. Source must be
from the reviewed Git commit; the package version 1.3.0 alone is insufficient.

## One configuration

Copy `examples/deploy/deployment.example.json` outside the repository. Choose a
dedicated non-root user and unused UID/GID, a private home outside Git, a separate
new runtime prefix and a free loopback port. Paths use canonical Linux spelling
without spaces or shell/systemd expansion characters. The file contains no
passwords, provider secrets, tokens or signing keys.

```bash
mkdir -m 700 "$HOME/hunterqa-deployment"
cp examples/deploy/deployment.example.json "$HOME/hunterqa-deployment/spec.json"
mkdir -m 700 "$HOME/hunterqa-deployment/rendered"
python3 tools/render_deployment.py --config "$HOME/hunterqa-deployment/spec.json" \
  --out-dir "$HOME/hunterqa-deployment/rendered"
```

The renderer emits `runtime.env` for Compose and `hunterqa-alpha.service` for
systemd. It refuses an occupied output directory. Neither output activates SSO,
creates a user or certifies security. Keep the rendered files and specification
together. Regenerate both after a configuration change; do not run both servers
against the same workspace simultaneously.

For the unchanged example, provision a **new** home and account. Check that the
names/IDs are free first; choose other values in the specification if needed.
Run the following only for a new installation, not over existing state:

```bash
set -eu
sudo test ! -e /srv/hunterqa-alpha
sudo groupadd --gid 10001 hunterqa-alpha
sudo useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent hunterqa-alpha
sudo install -d -m 700 -o 10001 -g 10001 /srv/hunterqa-alpha
sudo install -d -m 700 -o 10001 -g 10001 /srv/hunterqa-alpha/control \
  /srv/hunterqa-alpha/data /srv/hunterqa-alpha/backups /srv/hunterqa-alpha/runtime-home
```

`control` holds identity/configuration/key files; `data` holds the dashboard and
approved assessments; `backups` holds private archives. All belong to that
workspace's UID. `runtime-home` is a private tool cache, not another approved
assessment root. This layout permits original-path recovery inside the parent
bind mount. Existing separately located workspaces continue to use the original
CLI/service setup; this profile does not migrate, overwrite or adopt them.

## Native systemd

The installer targets a fresh prefix and refuses an existing environment. It
installs the same project extras, Semgrep, compiler/research packages and Chromium
used by the Docker build. Installing packages/browser binaries needs internet;
offline local operation is possible after dependencies are provisioned.

```bash
sudo sh tools/install_linux_runtime.sh --system-deps /opt/hunterqa-runtime
sudo -u hunterqa-alpha env HUNTERQA_OPERATOR_ROOT=/srv/hunterqa-alpha/control \
  /opt/hunterqa-runtime/bin/hunterqa workspace-init --workspace-id alpha \
  --root /srv/hunterqa-alpha/data --username admin --authorized
sudo cp "$HOME/hunterqa-deployment/rendered/hunterqa-alpha.service" /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/hunterqa-alpha.service
sudo systemctl daemon-reload
sudo systemctl enable --now hunterqa-alpha
sudo systemctl status hunterqa-alpha
```

Enter the administrator password at the private prompt. No registration endpoint
or default account/password is created. The unit checks actual UID/GID/group
membership before starting, uses a private temporary directory, read-only system
paths, no additional capabilities and bounded CPU/memory/tasks. Its post-start
probe waits for the loopback login handler; it does not authenticate at an IdP.

If system packages and browser libraries were separately provisioned, use
`--existing-system-deps` instead. This mode still installs Python packages and
Chromium; it is not a fully offline installer. For upgrades, install a new prefix,
back up state, regenerate the unit, and test before switching. Do not overwrite a
running virtual environment.

### Temporary Semgrep dependency repair

The current supplier release pins `mcp` and OpenTelemetry versions for which our
installed-package audit reported advisories. The shared installer prepares
`semgrep==1.185.0+hunterqa.1` from the official 1.185.0 wheel after checking its
PyPI SHA-256. It changes six dependency requirements and distribution version,
rebuilds RECORD, and retains vendor payload bytes, executable modes and licenses.
Its provenance records the original digest and replacements. This is a local
compatibility patch, **not an upstream-supported release**. Do not replace it with
an arbitrary wheel or silently ignore the supplier's dependency constraints.

Both deployment jobs require dependency consistency, real Semgrep findings and
an advisory audit of their actual installed Python inventories. The audit maps
the unchanged Semgrep code to its published base release; it does not skip that
component. Only the local HunterQA application is checked separately by source
QA. Review/remove this policy when a compatible supplier release adopts the
fixed dependencies. The manifests do not independently certify OS packages or
all unused upstream Semgrep subcommands.

## Docker Compose

Docker Engine and Compose v2 are required. Use the same specification and the
same already provisioned private home. No native Python application runtime or
systemd service is needed in this mode.

```bash
docker compose --env-file "$HOME/hunterqa-deployment/rendered/runtime.env" \
  -f examples/deploy/compose.yaml -p hunterqa-alpha build --pull
docker compose --env-file "$HOME/hunterqa-deployment/rendered/runtime.env" \
  -f examples/deploy/compose.yaml -p hunterqa-alpha run --rm app \
  workspace-init --workspace-id alpha --root /srv/hunterqa-alpha/data --username admin --authorized
docker compose --env-file "$HOME/hunterqa-deployment/rendered/runtime.env" \
  -f examples/deploy/compose.yaml -p hunterqa-alpha up -d --wait
```

Skip `workspace-init` when switching an existing profile from native mode: its
identity/data paths and keys stay the same. Stop systemd before starting Compose,
and stop Compose before restarting systemd. The application lease rejects a
second supported server, but it does not coordinate unrelated CLI writers.

The image runs as the specified non-root UID/GID, drops capabilities, uses
`no-new-privileges`, a read-only root filesystem, bounded temporary storage and
resource limits matching the unit. Only this workspace's private parent is
mounted. No Docker socket, host home or other workspace is mounted. Pin the
reviewed base image digest through `HUNTERQA_PYTHON_IMAGE` and retain the built
image ID plus `pip freeze` before accepting a deployment; version ranges/base
tags alone do not produce an immutable dependency lock.

The initial profile uses **host networking** to preserve the application's
existing loopback admission and fixed local-tool endpoints. It deliberately does
not publish a port or bind the application to all interfaces. It also does not
provide a separate network namespace or an egress firewall. Host networking is a
documented tradeoff, not tenant network-isolation evidence. See
[Docker host-network documentation](https://docs.docker.com/engine/network/drivers/host/).

## WSL2 and Docker Desktop

Use a Linux WSL2 distribution and Docker Desktop's **WSL2 engine/integration**
with Linux containers. Keep the checkout and private workspace on the Linux
filesystem, preserve Linux owners/modes, and verify numeric ownership from both
WSL and a container before initialization. Do not substitute a Windows Python
environment for the Linux runtime.

This host-network profile requires Docker Desktop 4.34+ with host networking
enabled. It is incompatible with Enhanced Container Isolation, and Desktop's
host networking supports TCP/UDP rather than lower-level protocols. The Docker
VMM backend has different bind-mount restrictions and is not this WSL2 profile.
Follow [Docker's WSL2 setup](https://docs.docker.com/desktop/features/wsl/) and
[host-network limitations](https://docs.docker.com/engine/network/drivers/host/#limitations).
Actual Desktop/WSL2 validation remains required; Linux CI is not that evidence.

## Authentication, TLS and offline behavior

The baseline is `http://127.0.0.1:8081`. Existing local login and offline source,
evidence and recovery functions do not depend on Google, Microsoft or an AI
provider. Downloaded tools/models and provider-dependent assessments have their
own requirements. An Ollama service/model is external and is not silently
downloaded or contacted by workspace mode, which keeps shared local AI disabled.

For the existing hosted OIDC profile, follow [operator SSO](OPERATOR_SSO.md) and
[the authenticated TLS edge](PRODUCTION_WORKSPACES.md). Both runtime modes use
that same private workspace configuration. A real certificate/proxy and registered
client remain necessary. This stage does not relax the current SSO-only hosted
restriction to expose password-only administrator access. Multi-provider/local
switches and administrator MFA must be completed before claiming the requested
production authentication policy.

## Operations and troubleshooting

| Symptom | Check |
| --- | --- |
| Wrong UID/GID or permission denied | Compare spec, `id hunterqa-alpha`, ownership and container UID; do not make control files world-readable |
| Runtime prefix already exists | Choose a new prefix; preserve the previous runtime for rollback |
| App cannot bind | Stop the other runtime and check the selected loopback port |
| Container unhealthy | Inspect `docker compose logs`; health verifies the login handler, not provider login or application completeness |
| systemd start fails | Check `journalctl -u hunterqa-alpha`, identity precheck and runtime dependencies |
| Chromium fails | Verify installed browser libraries, matching browser path and available temporary memory/tasks |
| Docker Desktop cannot reach localhost | Verify WSL2 engine/integration, Linux containers, host-network opt-in and ECI incompatibility |
| Remote access required | Configure the reviewed HTTPS/OIDC edge; do not change the backend to `0.0.0.0` to bypass admission |
| Backup or restore fails | Stop service/writers and follow [original-path recovery](WORKSPACE_RECOVERY.md); archives contain secrets and are not encrypted |

The deployment CI runs the same opt-in owned acceptance script under an actual
systemd unit and Compose: dependency inventory, local login/RBAC, a real source
worker, reports/export, Chromium login/logout, offline backup/restore and renewed
login. It does not prove every optional module against real targets, real
Google/Entra MFA, Windows behavior, hostile-tenant isolation or production load.
The owned fixture UID has non-loopback IPv4/IPv6 egress rejected during these
flows, while dependency builders and the advisory auditor retain network access.
This simulates offline local operation; it is a test-only policy, not an egress
firewall installed by the production profile.
Research binaries are inventoried; debugger/fuzzer-specific sandbox capabilities
and external cloud/AD/AI services need separate acceptance. All earlier features
and their regression tests remain in place.
