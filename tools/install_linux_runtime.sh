#!/bin/sh
# Install one immutable runtime; never edits user data or an existing environment.
set -eu
if [ "$(uname -s)" != Linux ]; then
    echo 'Use Linux or WSL2, not a Windows Python environment.' >&2
    exit 2
fi
if [ "$#" -ne 2 ] || { [ "$1" != --system-deps ] && [ "$1" != --existing-system-deps ]; }; then
    echo 'Usage: install_linux_runtime.sh --system-deps|--existing-system-deps /absolute/new/runtime' >&2
    exit 2
fi
INSTALL_PREFIX=$2
SOURCE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); assert sys.version_info >= (3,11); assert p.is_absolute() and len(p.parts)>2 and ".." not in p.parts and not p.exists(); assert not any(v.is_symlink() or (v/".git").exists() for v in (p,*p.parents))' "$INSTALL_PREFIX"
if [ "$1" = --system-deps ]; then
    [ "$(id -u)" -eq 0 ] || { echo 'System packages require root; provision dependencies separately otherwise.' >&2; exit 2; }
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    # The checked-in file contains only fixed package names, one per line.
    xargs apt-get install -y --no-install-recommends < "$SOURCE_ROOT/examples/deploy/runtime-packages.txt"
fi
python3 -m venv "$INSTALL_PREFIX"
"$INSTALL_PREFIX/bin/python" -m pip install --disable-pip-version-check --no-cache-dir "$SOURCE_ROOT[browser,cloud,identity,network,production]" -r "$SOURCE_ROOT/examples/deploy/runtime-requirements.txt"
export PLAYWRIGHT_BROWSERS_PATH="$INSTALL_PREFIX/browsers"
if [ "$1" = --system-deps ]; then
    "$INSTALL_PREFIX/bin/python" -m playwright install --with-deps chromium
else
    "$INSTALL_PREFIX/bin/python" -m playwright install chromium
fi
mkdir -p "$INSTALL_PREFIX/share/hunterqa"
cp "$SOURCE_ROOT/tools/verify_deployment.py" "$INSTALL_PREFIX/share/hunterqa/verify_deployment.py"
chmod -R a+rX "$INSTALL_PREFIX/browsers" "$INSTALL_PREFIX/share"
echo 'Runtime installed. Provision a private workspace and validate before serving.'
