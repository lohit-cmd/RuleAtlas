#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then python3 -m venv .venv; fi
.venv/bin/python -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11+ required'"
if ! .venv/bin/python -c 'import yaml' >/dev/null 2>&1; then
  .venv/bin/python -m pip install -r requirements.txt
fi
if [ ! -f data/ruleatlas.db ]; then .venv/bin/python -m ruleatlas demo; fi
exec .venv/bin/python -m ruleatlas serve
