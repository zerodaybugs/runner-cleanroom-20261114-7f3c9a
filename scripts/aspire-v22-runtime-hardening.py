#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

EXPECTED_INPUT_RUN_SHA256 = "c8b83bbf3aa91ba91b73771cabea69c521cdbd7fe6f21beed84191bf8635da9a"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label} marker count={count}")
    return source.replace(old, new, 1)


def main() -> int:
    if len(sys.argv) not in (2, 3):
        raise SystemExit(f"usage: {sys.argv[0]} RUN_SH [RECEIPT_JSON]")

    run_path = pathlib.Path(sys.argv[1])
    receipt_path = pathlib.Path(sys.argv[2]) if len(sys.argv) == 3 else None
    before_bytes = run_path.read_bytes()
    before_sha = sha256(before_bytes)
    if before_sha != EXPECTED_INPUT_RUN_SHA256:
        raise SystemExit(f"unexpected v21 run input SHA-256: {before_sha}")

    source = before_bytes.decode("utf-8")
    source = replace_once(
        source,
        'EVIDENCE="$PWD/evidence-aspire120006-macos-v20-trusted-yarp"',
        'EVIDENCE="${ZDB_EVIDENCE_DIR:-$PWD/evidence-aspire120006-macos-v22-runtime-smoke}"',
        "evidence directory",
    )
    source = replace_once(
        source,
        'curl -fsS --connect-timeout 1 --max-time 2 "https://localhost:$dash/"',
        'curl --cacert "$DEV_CERT_PEM" -fsS --connect-timeout 1 --max-time 2 "https://localhost:$dash/"',
        "dashboard readiness",
    )
    source = replace_once(
        source,
        'curl -fsS --connect-timeout 1 --max-time 2 "https://localhost:$unusedhttps/"',
        'curl --cacert "$DEV_CERT_PEM" -fsS --connect-timeout 1 --max-time 2 "https://localhost:$unusedhttps/"',
        "trusted YARP readiness",
    )

    run_path.write_text(source, encoding="utf-8")
    after_bytes = run_path.read_bytes()
    after_sha = sha256(after_bytes)

    receipt = {
        "schema": "aspire-v22-runtime-hardening-receipt-v1",
        "inputRunSha256": before_sha,
        "outputRunSha256": after_sha,
        "changes": [
            "runtime evidence directory is selected by ZDB_EVIDENCE_DIR",
            "dashboard readiness uses the exact exported development CA",
            "trusted YARP readiness uses the exact exported development CA",
            "browser certificate bypass remains forbidden",
        ],
    }
    if receipt_path is not None:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
