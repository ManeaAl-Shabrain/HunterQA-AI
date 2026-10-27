#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p instance
if [[ -f instance/zeroscope.sqlite3 && ! -f instance/hunterqa.sqlite3 ]]; then
  cp -p instance/zeroscope.sqlite3 instance/hunterqa.sqlite3
  echo "Preserved existing database in instance/hunterqa.sqlite3"
else
  echo "No migration required. Existing databases were not overwritten."
fi
