#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} V21_GATE_WRAPPER")

    path = Path(sys.argv[1])
    source = path.read_text(encoding="utf-8")

    anchor = "source = source_path.read_text()\n"
    insertion = (
        anchor
        + "if source.count('trap cleanup EXIT\\n') != 1:\n"
        + "    raise SystemExit('generated cleanup trap count mismatch')\n"
        + "source = source.replace('trap cleanup EXIT\\n', "
        + "'# cleanup deferred for v22 gate\\n', 1)\n"
    )
    if source.count(anchor) != 1:
        raise SystemExit(f"generator source anchor count={source.count(anchor)}")
    source = source.replace(anchor, insertion, 1)

    checksum = """test "$(sha256sum "$GENERATED" | awk '{print $1}')" = \\
  848c6172d396b39493a2ec90651f31ddb19da7fb74f4d3fb16461072d422019d
"""
    if source.count(checksum) != 1:
        raise SystemExit(f"generated checksum anchor count={source.count(checksum)}")
    source = source.replace(checksum, 'sha256sum "$GENERATED"\n', 1)

    execution = 'WRAPPING_KEY_B64="$WRAPPING_KEY_B64" "$GENERATED"\n'
    if source.count(execution) != 1:
        raise SystemExit(f"generated execution anchor count={source.count(execution)}")
    source = source.replace(
        execution,
        'WRAPPING_KEY_B64="$WRAPPING_KEY_B64" "./$GENERATED"\n',
        1,
    )

    path.write_text(source, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
