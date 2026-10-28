# HunterQA AI 8.2 — Unified Local Release Candidate

This is the ONE cumulative source tree: Semgrep, local Ollama Qwen, source graph, optional AFL++ replay, ASan/UBSan parsing, unified triage, analyst reviews, research analytics, local campaigns, campaign history, trends, patch safety gate and release doctor.

## Kali installation / update

```bash
cd ~/Desktop/HunterQA-AI
git status --short
git fetch origin
git switch --track origin/release/hunterqa-ai-8-2-integrated
bash tools/setup_verify_kali.sh
```

If the branch already exists, use `git switch release/hunterqa-ai-8-2-integrated`. Never overwrite uncommitted work or the local SQLite DB. The setup script creates a local persistent session key (outside the repo), installs Python requirements, runs tests and doctor. It never changes your approved scope unless you choose the environment values.

## Launch (in new terminal)

```bash
cd ~/Desktop/HunterQA-AI
source .venv/bin/activate
export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"
export HUNTERQA_APPROVED_ROOTS="$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_CAMPAIGN_HISTORY_ROOT="$HOME/ZeroScope-AI/research-lab"
export HUNTERQA_TRIAGE_REPORT="$HOME/ZeroScope-AI/research-lab/verification/hunterqa_unified_triage.json"
python run.py
```

Open inside the Kali VM: `http://127.0.0.1:5000/`, `/analytics`, `/campaigns`, `/trends` and `/triage`.

## Source release ZIP

```bash
python tools/build_release.py --repo . --out "$HOME/Desktop/HunterQA-AI-8.2-source.zip"
unzip -t "$HOME/Desktop/HunterQA-AI-8.2-source.zip"
```

Inspect the archive before distributing. It excludes common runtime and secret files but is not a substitute for reviewing tracked source.

## Security and readiness

The HTTP dashboard must bind only to loopback. The first-party tooling is for local, explicitly authorized source projects. Saved crash replay still executes lab binaries and must be performed only in an isolated VM. Model suggestions are never automatically applied or executed. Research records do not imply distinct or confirmed vulnerabilities; zero-day confirmation remains human-led. Regression tests demonstrate specific checks, NOT 100% safety or discovery coverage. Release candidate status continues until tests and interactive browser smoke tests succeed on the target Kali machine.

## Rollback

Back up `instance/hunterqa.sqlite3` outside the repository before upgrades. To return to the previous code, switch to the prior Git branch or commit; do not overwrite the live database unless restoring a deliberate backup.
