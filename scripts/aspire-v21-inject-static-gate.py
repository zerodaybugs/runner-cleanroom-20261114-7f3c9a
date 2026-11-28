#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <v20-reconstruction-script>")

    path = Path(sys.argv[1])
    source = path.read_text(encoding="utf-8")
    old = "echo V20_PATCH_CHAIN_GATE=PASS\n"
    new = r'''V21_STATIC_DIR="$GITHUB_WORKSPACE/v21-static"
mkdir -p "$V21_STATIC_DIR"
for lane in first_patched current_net10_revert current_net11 natural_fix; do
  cp "$RUN" "$V21_STATIC_DIR/run-$lane.sh"
  python3 "$GITHUB_WORKSPACE/scripts/aspire-v21-lane-selector.py" \
    "$V21_STATIC_DIR/run-$lane.sh" \
    "$lane" \
    "$V21_STATIC_DIR/receipt-$lane.json"
  bash -n "$V21_STATIC_DIR/run-$lane.sh"
  python3 -m json.tool "$V21_STATIC_DIR/receipt-$lane.json" >/dev/null
  grep -Fq 'security add-trusted-cert' "$V21_STATIC_DIR/run-$lane.sh"
  grep -Fq '# V21 parallel lane:' "$V21_STATIC_DIR/run-$lane.sh"
  if grep -Fq -- '--trust --format PEM' "$V21_STATIC_DIR/run-$lane.sh"; then
    echo "interactive trust remains in $lane" >&2
    exit 31
  fi
  if grep -Fq -- '--ignore-certificate-errors' "$V21_STATIC_DIR/run-$lane.sh"; then
    echo "certificate bypass remains in $lane" >&2
    exit 32
  fi
done
python3 "$GITHUB_WORKSPACE/scripts/aspire-v21-receipt-gate.py" "$V21_STATIC_DIR"
echo V21_PARALLEL_STATIC_GATE=PASS
echo V20_PATCH_CHAIN_GATE=PASS
'''
    if source.count(old) != 1:
        raise SystemExit(f"v20 final anchor count={source.count(old)}")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


if __name__ == "__main__":
    main()
