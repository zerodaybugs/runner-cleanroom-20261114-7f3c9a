#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

EXPECTED_INPUT_SHA256 = "55c6470e32a2ed5602ff0a450a587966ad6f40b9a5b88eb7a4d3514edf235906"
EXPECTED_LANES = {
    "first_patched",
    "current_net10_revert",
    "current_net11",
    "natural_fix",
}


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <receipt-directory>")

    root = Path(sys.argv[1])
    receipts = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(root.glob("receipt-*.json"))]
    lanes = {receipt.get("lane") for receipt in receipts}
    if lanes != EXPECTED_LANES:
        raise SystemExit(f"lane set mismatch: {sorted(str(lane) for lane in lanes)}")
    hashes = {receipt.get("outputRunSha256") for receipt in receipts}
    if len(hashes) != len(EXPECTED_LANES):
        raise SystemExit("partition output hashes are not unique")
    for receipt in receipts:
        lane = receipt.get("lane")
        if receipt.get("inputRunSha256") != EXPECTED_INPUT_SHA256:
            raise SystemExit(f"unexpected input hash for {lane}")
        if receipt.get("schema") != 2:
            raise SystemExit(f"unexpected schema for {lane}")
        trust = receipt.get("certificateTrust") or {}
        if trust.get("store") != "/Library/Keychains/System.keychain":
            raise SystemExit(f"unexpected trust store for {lane}")
        if trust.get("addCommand") != "sudo -n security add-trusted-cert":
            raise SystemExit(f"unexpected trust command for {lane}")
        if trust.get("browserBypass") is not False:
            raise SystemExit(f"browser trust bypass detected for {lane}")
        if trust.get("validatedByRunId") != 46173931175:
            raise SystemExit(f"unvalidated certificate method for {lane}")
    print(json.dumps(receipts, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
