#!/bin/bash
set -euo pipefail
exec python3 /src/scripts/build_module.py "${1:?validated build plan required}"
