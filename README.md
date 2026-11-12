# HunterQA

A local workspace for authorized security assessments: review source code and saved evidence, run scoped checks, and prepare reports for review and retesting.

**Python 3.11+ · Linux / WSL2 · CLI and local dashboard**

[Setup guide](docs/PERSONAL_LOCALHOST_SETUP.md) · [Zero to Start](<zero to start.md>) · [Commands](docs/COMMAND_REFERENCE.md) · [Release status](docs/LOCAL_RELEASE_HANDOFF.md)

## What it includes

| Area | Available |
| --- | --- |
| Code review | Built-in checks, optional Semgrep and local Ollama suggestions |
| Web checks | Scoped HTTP and rendered-link discovery; controlled SQL/XSS canary checks |
| Evidence | Selected API, identity, cloud, network and configuration readers |
| Accounts | Local login, encrypted Admin MFA, optional Google and Entra OIDC, local roles |
| Reports | Analyst review, HTML/JSON/SARIF exports and retest comparisons |
| Operations | Separate workspaces, Linux Compose/systemd, backup and recovery |

Local login and supported local workflows work offline after installation. Google, Entra and external assessments need their respective services. No public domain, VPS or cloud hosting is required.

## 1. Choose a deployment

| Use | Start here |
| --- | --- |
| Personal Linux workspace | Follow the steps below |
| Linux Docker Compose or native systemd with the shared tool runtime | [Deployment guide](docs/LINUX_DEPLOYMENT.md) |
| Windows through WSL2 / Docker Desktop | [Personal setup](docs/PERSONAL_LOCALHOST_SETUP.md) |
| A first practice run without accounts or external targets | [Owned lab walkthrough](<zero to start.md>) |

## 2. Install the local application

In a Linux or WSL2 terminal:

```bash
git clone https://github.com/ManeaAl-Shabrain/HunterQA-AI.git
cd HunterQA-AI
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[identity,production]'
hunterqa --version
```

This installs the application and sign-in/server dependencies. The [shared deployment runtime](docs/LINUX_DEPLOYMENT.md) adds the optional assessment tools.

## 3. Create a private workspace

Use a new, empty data directory outside the repository:

```bash
umask 077
export HUNTERQA_OPERATOR_ROOT="$HOME/.local/share/hunterqa/control"
mkdir -p "$HUNTERQA_OPERATOR_ROOT"
chmod 700 "$HUNTERQA_OPERATOR_ROOT"
mkdir -m 700 "$HOME/hunterqa-local"

hunterqa workspace-init --workspace-id personal --root "$HOME/hunterqa-local" \
  --username admin --authorized
export HUNTERQA_WORKSPACE_CONFIG="$HUNTERQA_OPERATOR_ROOT/personal/workspace.json"
```

Enter a password of at least 14 characters when prompted. Existing workspaces should be opened with their saved configuration, not initialized again.

## 4. Enable login and MFA

```bash
hunterqa identity-setup --config "$HUNTERQA_WORKSPACE_CONFIG" \
  --origin http://localhost:8081 --authorized
hunterqa operator-mfa-enroll --database "$HUNTERQA_OPERATOR_ROOT/personal/operators.sqlite3" \
  --key-file "$HUNTERQA_OPERATOR_ROOT/personal/auth.key" --username admin --authorized
```

Add the private setup URI to your authenticator and confirm its code. Keep it out of screenshots, logs and Git. Google and Entra remain disabled until you configure them.

## 5. Start and use HunterQA

```bash
hunterqa workspace-check --config "$HUNTERQA_WORKSPACE_CONFIG"
hunterqa workspace-serve --require-auth-policy --config "$HUNTERQA_WORKSPACE_CONFIG" --port 8081
```

1. Open **http://localhost:8081** and sign in with your password and a fresh MFA code.
2. Place an approved project under `$HOME/hunterqa-local/assessments`.
3. Add its path in **Projects**, confirm authorization and start a scan.
4. Review the findings, then open the report or export the results.

Stop the foreground server with **Ctrl+C**. It listens on **127.0.0.1**. Use the Compose/systemd guide for a managed service. Standalone assessment commands use `HUNTERQA_APPROVED_ROOTS`; workspace serving sets its own approved assessment root.

## Important files

| File or guide | Purpose |
| --- | --- |
| [Personal setup](docs/PERSONAL_LOCALHOST_SETUP.md) | Local installation, Google/Entra registration and troubleshooting |
| [Deployment specification](examples/deploy/deployment.example.json) · [Compose](examples/deploy/compose.yaml) · [Installer](tools/install_linux_runtime.sh) | Shared Linux deployment files |
| [Authentication](docs/UNIFIED_AUTHENTICATION.md) · [Recovery](docs/WORKSPACE_RECOVERY.md) | Accounts, MFA, secrets, backup and restore |
| [Assessment guide](docs/AUTHORIZED_ASSESSMENT_BEGINNER_GUIDE.md) · [Templates](templates/README.md) | Scope, evidence and reporting |
| [Category index](docs/CATEGORY_REVIEW_INDEX.md) · [Feature checklist](docs/FEATURE_READINESS_CHECKLIST.md) | Implemented checks and remaining coverage |
| [Handoff and manual acceptance](docs/LOCAL_RELEASE_HANDOFF.md) | Tested release scope and owner-run checks |
| [Security policy](SECURITY.md) · [Versioning](docs/VERSIONING.md) | Reporting issues and identifying source builds |

## Status and scope

The personal localhost implementation has passed automated application and Linux deployment checks. Real Google/Entra sign-in and Windows WSL2/Desktop acceptance are owner-run checks. See the [handoff](docs/LOCAL_RELEASE_HANDOFF.md) for evidence and completion criteria.

- Findings are review candidates; coverage and real-world effectiveness are not guaranteed.
- Broader target SSO, AD/cloud coverage and distributed multi-user features remain [separate expansion work](docs/EXPANSION_PROGRESS.md).
- Use only systems you own or have explicit **written permission** to assess. `--authorized` records acknowledgement; it does not verify ownership.

The package still reports **1.3.0**. Current source includes changes beyond the original [v1.3.0 release](https://github.com/ManeaAl-Shabrain/HunterQA-AI/releases/tag/v1.3.0); record `git rev-parse HEAD` with your installation.
