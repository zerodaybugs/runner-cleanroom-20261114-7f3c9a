#!/usr/bin/env bash
set -euo pipefail

: "${WRAPPING_KEY_B64:?WRAPPING_KEY_B64 is required}"

BOOTSTRAP=scripts/aspire-v13-bootstrap.sh
EVIDENCE_DIR_FINAL="${ZDB_EVIDENCE_DIR:-evidence-aspire120006-macos-v23-instrumented}"
PROFILE="${ZDB_MATRIX_PROFILE:-smoke}"

test -f "$BOOTSTRAP"
test "$(shasum -a 256 "$BOOTSTRAP" | awk '{print $1}')" = \
  61573c91e0efcf1171ed45481c829c7f2e736b5e789bcb6f6a2335966ac8a99c
test "$(shasum -a 256 scripts/aspire-v16-final-harness.py | awk '{print $1}')" = \
  02142f2ef0706b36be7d024b09ba84857bb7580da919a5c49cc19f2b174973e6
test "$(shasum -a 256 scripts/aspire-v18-direct-apphost-harness.py | awk '{print $1}')" = \
  195bec386f284ed8456002d1a81637e46a42c5cc67213c10162864744cc065f1
test "$(shasum -a 256 scripts/aspire-v20-apply.sh | awk '{print $1}')" = \
  d5c0a2719e76431a2f7b31c6b6c065e4523041e57b4678ca346b5fe12ae320b1
test "$(shasum -a 256 scripts/aspire-v21-apply.sh | awk '{print $1}')" = \
  22051d15451929bb6f28a2efd491978c3855d24dfcd62881aef023fdf56c0b9b
test "$(shasum -a 256 scripts/aspire-v22-runtime-hardening.py | awk '{print $1}')" = \
  ab2bc7836d66b492a81e88103a078c873562022741060b29b1581a1588224921

python3 -m py_compile \
  scripts/aspire-v16-final-harness.py \
  scripts/aspire-v18-direct-apphost-harness.py \
  scripts/aspire-v22-runtime-hardening.py
bash -n scripts/aspire-v20-apply.sh
bash -n scripts/aspire-v21-apply.sh

python3 - "$BOOTSTRAP" "$EVIDENCE_DIR_FINAL" <<'PY_PATCH_BOOTSTRAP'
from pathlib import Path
import sys

path = Path(sys.argv[1])
final_evidence_dir = sys.argv[2]
source = path.read_text()
anchor = '''bash -n "$PATCHED_RUN"
node --check "$PATCHED_BROWSER"
'''
insertion = f'''bash -n "$PATCHED_RUN"
node --check "$PATCHED_BROWSER"
ORIGINAL_EVIDENCE_DIR="$EVIDENCE_DIR"
FINAL_EVIDENCE_DIR={final_evidence_dir!r}
mkdir -p "$FINAL_EVIDENCE_DIR"
cp -R "$ORIGINAL_EVIDENCE_DIR"/. "$FINAL_EVIDENCE_DIR"/
EVIDENCE_DIR="$FINAL_EVIDENCE_DIR"
CHECKPOINTS="$EVIDENCE_DIR/PATCH_CHAIN_CHECKPOINTS.txt"
: > "$CHECKPOINTS"

record_sha() {{
  local label="$1" file="$2" expected="$3" actual
  actual="$(shasum -a 256 "$file" | awk '{{print $1}}')"
  printf '%s_ACTUAL=%s\\n%s_EXPECTED=%s\\n' "$label" "$actual" "$label" "$expected" >> "$CHECKPOINTS"
  if [[ "$actual" != "$expected" ]]; then
    printf 'SHA_MISMATCH label=%s actual=%s expected=%s file=%s\\n' "$label" "$actual" "$expected" "$file" >&2
    return 93
  fi
}}

ORIGINAL_PATCHED_RUN_SHA="$PATCHED_RUN_SHA"
ORIGINAL_PATCHED_BROWSER_SHA="$PATCHED_BROWSER_SHA"
record_sha V13_RUN "$PATCHED_RUN" "$ORIGINAL_PATCHED_RUN_SHA"
record_sha V13_BROWSER "$PATCHED_BROWSER" "$ORIGINAL_PATCHED_BROWSER_SHA"

python3 scripts/aspire-v16-final-harness.py "$PATCHED_RUN" "$EVIDENCE_DIR/HARNESS_V16_PATCH.json"
record_sha V16_RUN "$PATCHED_RUN" "ab129da6a4cfcaff8b4001722b3f5220d0ea9d7be6e225a921ebfba776ffb2b1"
V16_RUN_SHA="$(shasum -a 256 "$PATCHED_RUN" | awk '{{print $1}}')"

python3 scripts/aspire-v18-direct-apphost-harness.py "$PATCHED_RUN" "$EVIDENCE_DIR/HARNESS_V18_DIRECT_PATCH.json"
record_sha V18_RUN "$PATCHED_RUN" "44b49d845c735f3d04dc62bea8f974f0479020cc3e258d613ecad6e946f98eca"
record_sha V18_BROWSER "$PATCHED_BROWSER" "01ce64c7b23a96add883d6d2f96725af5b5158116dd37dff2382a6979a4b7174"
V18_RUN_SHA="$(shasum -a 256 "$PATCHED_RUN" | awk '{{print $1}}')"

scripts/aspire-v20-apply.sh "$PATCHED_RUN" "$PATCHED_BROWSER" "$EVIDENCE_DIR/HARNESS_V20_PATCH.json" > "$EVIDENCE_DIR/HARNESS_V20_PATCH.stdout" 2> "$EVIDENCE_DIR/HARNESS_V20_PATCH.stderr"
record_sha V20_RUN "$PATCHED_RUN" "55c6470e32a2ed5602ff0a450a587966ad6f40b9a5b88eb7a4d3514edf235906"
record_sha V20_BROWSER "$PATCHED_BROWSER" "e9e33b5ef3a3f3f08779af526bd91fa633f0f52f2f4676d51eb8add2c4eeefbe"
V20_RUN_SHA="$(shasum -a 256 "$PATCHED_RUN" | awk '{{print $1}}')"
V20_BROWSER_SHA="$(shasum -a 256 "$PATCHED_BROWSER" | awk '{{print $1}}')"

scripts/aspire-v21-apply.sh "$PATCHED_RUN" "$PATCHED_BROWSER" "$EVIDENCE_DIR/HARNESS_V21_PATCH.json" > "$EVIDENCE_DIR/HARNESS_V21_PATCH.stdout" 2> "$EVIDENCE_DIR/HARNESS_V21_PATCH.stderr"
record_sha V21_RUN "$PATCHED_RUN" "c8b83bbf3aa91ba91b73771cabea69c521cdbd7fe6f21beed84191bf8635da9a"
record_sha V21_BROWSER "$PATCHED_BROWSER" "a5553a24a95f9bd1b4f340e5acdcd6ee8d63588d875700ce0024ed659005351e"
V21_RUN_SHA="$(shasum -a 256 "$PATCHED_RUN" | awk '{{print $1}}')"
V21_BROWSER_SHA="$(shasum -a 256 "$PATCHED_BROWSER" | awk '{{print $1}}')"

python3 scripts/aspire-v22-runtime-hardening.py "$PATCHED_RUN" "$EVIDENCE_DIR/HARNESS_V22_PATCH.json" > "$EVIDENCE_DIR/HARNESS_V22_PATCH.stdout" 2> "$EVIDENCE_DIR/HARNESS_V22_PATCH.stderr"
record_sha V22_RUN "$PATCHED_RUN" "15d852ebaab817a79954a0687d9dff18beb0efd6bd8c9a4dc44a2e426c40b2d7"
record_sha V22_BROWSER "$PATCHED_BROWSER" "a5553a24a95f9bd1b4f340e5acdcd6ee8d63588d875700ce0024ed659005351e"
PATCHED_RUN_SHA="$(shasum -a 256 "$PATCHED_RUN" | awk '{{print $1}}')"
PATCHED_BROWSER_SHA="$(shasum -a 256 "$PATCHED_BROWSER" | awk '{{print $1}}')"

bash -n "$PATCHED_RUN"
node --check "$PATCHED_BROWSER"
printf '%s  product-patched-run.sh\\n%s  product-patched-browser.js\\n%s  v16-hardened-run.sh\\n%s  v18-direct-run.sh\\n%s  v20-trusted-yarp-run.sh\\n%s  v20-trusted-yarp-browser.js\\n%s  v21-natural-discovery-run.sh\\n%s  v21-natural-discovery-browser.js\\n%s  final-v22-runtime-run.sh\\n%s  final-v22-runtime-browser.js\\n' "$ORIGINAL_PATCHED_RUN_SHA" "$ORIGINAL_PATCHED_BROWSER_SHA" "$V16_RUN_SHA" "$V18_RUN_SHA" "$V20_RUN_SHA" "$V20_BROWSER_SHA" "$V21_RUN_SHA" "$V21_BROWSER_SHA" "$PATCHED_RUN_SHA" "$PATCHED_BROWSER_SHA" > "$EVIDENCE_DIR/executed-run-hashes.txt"
printf 'PATCH_CHAIN_STATUS=PASS\\n' >> "$CHECKPOINTS"

if [[ "${{ZDB_PATCH_ONLY:-0}}" == "1" ]]; then
  echo PATCH_ONLY_CHAIN=PASS
  exit 0
fi
'''
if source.count(anchor) != 1:
    raise SystemExit(f'bootstrap anchor count={source.count(anchor)}')
path.write_text(source.replace(anchor, insertion, 1))
PY_PATCH_BOOTSTRAP

bash -n "$BOOTSTRAP"
chmod 700 \
  "$BOOTSTRAP" \
  scripts/aspire-v16-final-harness.py \
  scripts/aspire-v18-direct-apphost-harness.py \
  scripts/aspire-v20-apply.sh \
  scripts/aspire-v21-apply.sh \
  scripts/aspire-v22-runtime-hardening.py

export ZDB_MATRIX_PROFILE="$PROFILE"
export ZDB_EVIDENCE_DIR="$EVIDENCE_DIR_FINAL"
"$BOOTSTRAP"
