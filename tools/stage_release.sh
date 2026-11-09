#!/bin/bash
# Record a successful gate from this invocation only; S1 remains ineligible.
set -eu
binary=$1 commit=$2 target=$3 artifact=$4
rm -f "$artifact/ready" "$artifact/refused.log"
if python3 "$(dirname "$0")/release_gate.py" "$binary" "$commit" "$target" > "$artifact/gate.log" 2>&1; then
  touch "$artifact/ready"
else
  cat "$artifact/gate.log"
  grep -Fx 'ccs: conformance is not implemented in S1' "$artifact/gate.log"
  test ! -e "$artifact/ready"
  echo 'PASS negative: publication gate refused the S1 skeleton' | tee "$artifact/refused.log"
fi
