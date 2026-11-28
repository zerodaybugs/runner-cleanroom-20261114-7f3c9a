#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import shlex
import sys
from pathlib import Path

EXPECTED_BOOTSTRAP_SHA256 = "61573c91e0efcf1171ed45481c829c7f2e736b5e789bcb6f6a2335966ac8a99c"
EXPECTED_V16_RUN_SHA256 = "ab129da6a4cfcaff8b4001722b3f5220d0ea9d7be6e225a921ebfba776ffb2b1"
EXPECTED_V18_RUN_SHA256 = "44b49d845c735f3d04dc62bea8f974f0479020cc3e258d613ecad6e946f98eca"
EXPECTED_V18_BROWSER_SHA256 = "01ce64c7b23a96add883d6d2f96725af5b5158116dd37dff2382a6979a4b7174"
EXPECTED_V20_RUN_SHA256 = "55c6470e32a2ed5602ff0a450a587966ad6f40b9a5b88eb7a4d3514edf235906"
EXPECTED_V20_BROWSER_SHA256 = "e9e33b5ef3a3f3f08779af526bd91fa633f0f52f2f4676d51eb8add2c4eeefbe"
EXPECTED_V21_RUN_SHA256 = {
    "first_patched": "c79e6cf67b64e7c733f7c238d1ec1911c3dc49f0118c01abecfd417251e69480",
    "current_net10_revert": "93af3e00ec7f6135b89c41e76843acb4bf5ef7e15ead57f8a4cf9e0a20b0877f",
    "current_net11": "94612be4876e7f5447c7e4e705cefcd4bf35019306149ded3759a1067fe10f81",
    "natural_fix": "be2aca9a6fed4d546ab5a805ee8ea1be87c0729fbe3f15533f1b45134496c011",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit(f"usage: {sys.argv[0]} <aspire-v13-bootstrap.sh> <lane> <receipt.json>")

    bootstrap_path = Path(sys.argv[1])
    lane = sys.argv[2]
    receipt_path = Path(sys.argv[3])
    if lane not in EXPECTED_V21_RUN_SHA256:
        raise SystemExit(f"unsupported lane: {lane}")

    original = bootstrap_path.read_bytes()
    original_sha = sha256_bytes(original)
    if original_sha != EXPECTED_BOOTSTRAP_SHA256:
        raise SystemExit(f"unexpected bootstrap hash: {original_sha}")
    source = original.decode("utf-8")

    anchor = 'bash -n "$PATCHED_RUN"\nnode --check "$PATCHED_BROWSER"\n'
    if source.count(anchor) != 1:
        raise SystemExit(f"bootstrap anchor count={source.count(anchor)}")

    lane_q = shlex.quote(lane)
    evidence_directory = f"evidence-aspire120006-macos-v21-{lane}"
    expected_final_run = EXPECTED_V21_RUN_SHA256[lane]
    insertion = f'''bash -n "$PATCHED_RUN"
node --check "$PATCHED_BROWSER"
ORIGINAL_EVIDENCE_DIR="$EVIDENCE_DIR"
FINAL_EVIDENCE_DIR={shlex.quote(evidence_directory)}
mkdir -p "$FINAL_EVIDENCE_DIR"
if [[ -d "$ORIGINAL_EVIDENCE_DIR" ]]; then
  cp -R "$ORIGINAL_EVIDENCE_DIR"/. "$FINAL_EVIDENCE_DIR"/
fi
EVIDENCE_DIR="$FINAL_EVIDENCE_DIR"
ORIGINAL_PATCHED_RUN_SHA="$PATCHED_RUN_SHA"
ORIGINAL_PATCHED_BROWSER_SHA="$PATCHED_BROWSER_SHA"
python3 scripts/aspire-v16-final-harness.py "$PATCHED_RUN" "$EVIDENCE_DIR/HARNESS_V16_PATCH.json"
V16_RUN_SHA="$(shasum -a 256 "$PATCHED_RUN" | awk '{{print $1}}')"
test "$V16_RUN_SHA" = "{EXPECTED_V16_RUN_SHA256}"
python3 scripts/aspire-v18-direct-apphost-harness.py "$PATCHED_RUN" "$EVIDENCE_DIR/HARNESS_V18_DIRECT_PATCH.json"
V18_RUN_SHA="$(shasum -a 256 "$PATCHED_RUN" | awk '{{print $1}}')"
test "$V18_RUN_SHA" = "{EXPECTED_V18_RUN_SHA256}"
test "$(shasum -a 256 "$PATCHED_BROWSER" | awk '{{print $1}}')" = "{EXPECTED_V18_BROWSER_SHA256}"
scripts/aspire-v20-apply.sh "$PATCHED_RUN" "$PATCHED_BROWSER" "$EVIDENCE_DIR/HARNESS_V20_PATCH.json" > "$EVIDENCE_DIR/HARNESS_V20_PATCH.stdout" 2> "$EVIDENCE_DIR/HARNESS_V20_PATCH.stderr"
V20_RUN_SHA="$(shasum -a 256 "$PATCHED_RUN" | awk '{{print $1}}')"
V20_BROWSER_SHA="$(shasum -a 256 "$PATCHED_BROWSER" | awk '{{print $1}}')"
test "$V20_RUN_SHA" = "{EXPECTED_V20_RUN_SHA256}"
test "$V20_BROWSER_SHA" = "{EXPECTED_V20_BROWSER_SHA256}"
python3 scripts/aspire-v21-lane-selector.py "$PATCHED_RUN" {lane_q} "$EVIDENCE_DIR/HARNESS_V21_LANE_SELECTOR.json"
PATCHED_RUN_SHA="$(shasum -a 256 "$PATCHED_RUN" | awk '{{print $1}}')"
PATCHED_BROWSER_SHA="$(shasum -a 256 "$PATCHED_BROWSER" | awk '{{print $1}}')"
test "$PATCHED_RUN_SHA" = "{expected_final_run}"
test "$PATCHED_BROWSER_SHA" = "{EXPECTED_V20_BROWSER_SHA256}"
bash -n "$PATCHED_RUN"
node --check "$PATCHED_BROWSER"
python3 -m json.tool "$EVIDENCE_DIR/HARNESS_V16_PATCH.json" >/dev/null
python3 -m json.tool "$EVIDENCE_DIR/HARNESS_V18_DIRECT_PATCH.json" >/dev/null
python3 -m json.tool "$EVIDENCE_DIR/HARNESS_V20_PATCH.json" >/dev/null
python3 -m json.tool "$EVIDENCE_DIR/HARNESS_V21_LANE_SELECTOR.json" >/dev/null
printf '%s  product-patched-run.sh\\n%s  product-patched-browser.js\\n%s  v16-hardened-run.sh\\n%s  v18-direct-run.sh\\n%s  v20-trusted-yarp-run.sh\\n%s  final-v21-lane-run.sh\\n%s  final-v21-browser.js\\n' \
  "$ORIGINAL_PATCHED_RUN_SHA" \
  "$ORIGINAL_PATCHED_BROWSER_SHA" \
  "$V16_RUN_SHA" \
  "$V18_RUN_SHA" \
  "$V20_RUN_SHA" \
  "$PATCHED_RUN_SHA" \
  "$PATCHED_BROWSER_SHA" > "$EVIDENCE_DIR/executed-run-hashes.txt"
printf 'LANE=%s\\nEVIDENCE_DIR=%s\\nFINAL_RUN_SHA256=%s\\nFINAL_BROWSER_SHA256=%s\\n' \
  {lane_q} \
  "$EVIDENCE_DIR" \
  "$PATCHED_RUN_SHA" \
  "$PATCHED_BROWSER_SHA" > "$EVIDENCE_DIR/v21-lane-contract.txt"
'''

    patched = source.replace(anchor, insertion, 1)
    patched_bytes = patched.encode("utf-8")
    bootstrap_path.write_bytes(patched_bytes)

    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema": 1,
        "lane": lane,
        "inputBootstrapSha256": original_sha,
        "outputBootstrapSha256": sha256_bytes(patched_bytes),
        "evidenceDirectory": evidence_directory,
        "expectedFinalRunSha256": expected_final_run,
        "expectedFinalBrowserSha256": EXPECTED_V20_BROWSER_SHA256,
        "patchChain": {
            "v16RunSha256": EXPECTED_V16_RUN_SHA256,
            "v18RunSha256": EXPECTED_V18_RUN_SHA256,
            "v18BrowserSha256": EXPECTED_V18_BROWSER_SHA256,
            "v20RunSha256": EXPECTED_V20_RUN_SHA256,
            "v20BrowserSha256": EXPECTED_V20_BROWSER_SHA256,
        },
        "scope": "orchestration only; preserves the verified product PoC, stock Dashboard navigation, stock lifecycle sink, and all lane assertions",
    }
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(receipt["outputBootstrapSha256"])


if __name__ == "__main__":
    main()
