#!/bin/sh
set -eu
umask 077
exec "$HUNTERQA_RUNTIME_PREFIX/bin/hunterqa" "$@"
