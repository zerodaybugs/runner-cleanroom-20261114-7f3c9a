#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

EXPECTED_INPUT_RUN_SHA256 = "15d852ebaab817a79954a0687d9dff18beb0efd6bd8c9a4dc44a2e426c40b2d7"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if len(sys.argv) not in (2, 3):
        raise SystemExit(f"usage: {sys.argv[0]} RUN_SH [RECEIPT_JSON]")

    run_path = Path(sys.argv[1])
    receipt_path = Path(sys.argv[2]) if len(sys.argv) == 3 else None

    before = run_path.read_bytes()
    before_sha = sha256(before)
    if before_sha != EXPECTED_INPUT_RUN_SHA256:
        raise SystemExit(f"unexpected v22 run input SHA-256: {before_sha}")

    source = before.decode("utf-8")
    old = 'EVIDENCE="${ZDB_EVIDENCE_DIR:-$PWD/evidence-aspire120006-macos-v22-runtime-smoke}"\nmkdir -p "$WORK" "$EVIDENCE"\n'
    new = '''EVIDENCE="${ZDB_EVIDENCE_DIR:-$PWD/evidence-aspire120006-macos-v24-runtime-smoke}"
case "$EVIDENCE" in
  /*) ;;
  *) EVIDENCE="$PWD/$EVIDENCE" ;;
esac
mkdir -p "$WORK" "$EVIDENCE"
'''
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"evidence path marker count={count}")
    source = source.replace(old, new, 1)

    run_path.write_text(source, encoding="utf-8")
    after = run_path.read_bytes()
    after_sha = sha256(after)

    receipt = {
        "schema": "aspire-v24-evidence-path-hardening-receipt-v1",
        "inputRunSha256": before_sha,
        "outputRunSha256": after_sha,
        "changes": [
            "normalize a relative ZDB_EVIDENCE_DIR against the initial working directory before any cd",
            "preserve an explicitly absolute evidence directory unchanged",
            "create the normalized evidence directory before certificate, build, and lane logging",
            "leave product source, browser logic, attacker model, and security assertions unchanged",
        ],
    }

    if receipt_path is not None:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
