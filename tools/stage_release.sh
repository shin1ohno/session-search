#!/bin/bash
# Record a successful gate from this invocation only.
set -euo pipefail
binary=$1 commit=$2 target=$3 artifact=$4
rm -f "$artifact/ready" "$artifact/refused.log"
if python3 "$(dirname "$0")/release_gate.py" "$binary" "$commit" "$target" > "$artifact/gate.log" 2>&1; then
  touch "$artifact/ready"
else
  cp "$artifact/gate.log" "$artifact/refused.log"
  cat "$artifact/refused.log"
  exit 1
fi
