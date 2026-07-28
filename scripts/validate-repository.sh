#!/usr/bin/env bash
# Cross-platform launcher for scripts/validate_repository.py
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "Python 3 is required" >&2
  exit 1
fi
exec "$PY" "$ROOT/scripts/validate_repository.py" "$@"
