#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m compileall -q hunterqa
python -m pytest -q
python -m hunterqa doctor --check-ollama
python - <<'PY'
from hunterqa import create_app
app = create_app({"TESTING": True})
with app.test_client() as client:
    for route in ("/", "/research", "/triage", "/analytics", "/campaigns",
                  "/trends", "/cve-intelligence"):
        response = client.get(route)
        if response.status_code != 200:
            raise SystemExit(f"FAIL: {route} -> {response.status_code}")
        print("PASS:", route)
PY
echo "Release checks complete. Review all warnings before approval."
