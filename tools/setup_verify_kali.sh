#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
if [[ ! -d .venv ]]; then python3 -m venv .venv; fi
source .venv/bin/activate
python -m pip install -e '.[dev]'
mkdir -p "$HOME/.config/hunterqa"
chmod 700 "$HOME/.config/hunterqa"
key="$HOME/.config/hunterqa/session-key"
if [[ ! -e "$key" ]]; then
  ( umask 077; python3 -c 'import secrets;print(secrets.token_hex(32))' > "$key" )
fi
chmod 600 "$key"
export HUNTERQA_SECRET_KEY="$(cat "$key")"
export HUNTERQA_APPROVED_ROOTS="${HUNTERQA_APPROVED_ROOTS:-$HOME/ZeroScope-AI/targets:$HOME/ZeroScope-AI/research-lab}"
export HUNTERQA_CAMPAIGN_HISTORY_ROOT="${HUNTERQA_CAMPAIGN_HISTORY_ROOT:-$HOME/ZeroScope-AI/research-lab}"
python -m compileall -q hunterqa
python -m pytest -q
python -m hunterqa doctor --check-ollama
echo 'Checks complete. Launch dashboard with: source .venv/bin/activate; export HUNTERQA_SECRET_KEY="$(cat "$HOME/.config/hunterqa/session-key")"; python run.py'
