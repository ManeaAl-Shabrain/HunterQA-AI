#!/bin/sh
set -eu
exec "$HUNTERQA_RUNTIME_PREFIX/bin/python" "$HUNTERQA_RUNTIME_PREFIX/share/hunterqa/verify_deployment.py" --phase health
