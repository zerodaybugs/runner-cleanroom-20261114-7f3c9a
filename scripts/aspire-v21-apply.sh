#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: $0 <run.sh> <browser.js> <receipt.json>" >&2
  exit 64
fi

RUN_PATH="$1"
BROWSER_PATH="$2"
RECEIPT_PATH="$3"

test -f "$RUN_PATH"
test -f "$BROWSER_PATH"
test -f private.pem

v21_get() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
    sealed/aspire-v21-natural-discovery-patcher.metadata
}

cleanup_v21() {
  rm -rf \
    v21-patch.enc.b64.norm v21-patch.enc \
    v21-patch.key.enc v21-patch.runtime.key \
    v21-patch.zip v21-patch
}
trap cleanup_v21 EXIT

INPUT_RUN_SHA="$(shasum -a 256 "$RUN_PATH" | awk '{print $1}')"
INPUT_BROWSER_SHA="$(shasum -a 256 "$BROWSER_PATH" | awk '{print $1}')"
test "$INPUT_RUN_SHA" = "$(v21_get INPUT_RUN_SHA256)"
test "$INPUT_BROWSER_SHA" = "$(v21_get INPUT_BROWSER_SHA256)"

cat sealed/aspire-v21-natural-discovery-patcher.enc.b64.part-* | tr -d '\r\n ' > v21-patch.enc.b64.norm
test "$(shasum -a 256 v21-patch.enc.b64.norm | awk '{print $1}')" = \
  "$(v21_get PATCH_B64_NORMALIZED_SHA256)"
openssl base64 -d -A -in v21-patch.enc.b64.norm -out v21-patch.enc
test "$(shasum -a 256 v21-patch.enc | awk '{print $1}')" = \
  "$(v21_get PATCH_CIPHER_SHA256)"

tr -d '\r\n ' < sealed/aspire-v21-natural-discovery-patcher.key.enc.b64 | \
  openssl base64 -d -A > v21-patch.key.enc
test "$(shasum -a 256 v21-patch.key.enc | awk '{print $1}')" = \
  "$(v21_get PATCH_KEY_CIPHER_SHA256)"
openssl pkeyutl -decrypt \
  -inkey private.pem \
  -in v21-patch.key.enc \
  -out v21-patch.runtime.key \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256
test "$(wc -c < v21-patch.runtime.key | tr -d ' ')" = 32

V21_KEY_HEX="$(od -An -tx1 -v v21-patch.runtime.key | tr -d ' \n')"
V21_IV_HEX="$(v21_get PATCH_IV_HEX)"
test "${#V21_IV_HEX}" = 32
openssl enc -d -aes-256-cbc \
  -K "$V21_KEY_HEX" \
  -iv "$V21_IV_HEX" \
  -in v21-patch.enc \
  -out v21-patch.zip
test "$(shasum -a 256 v21-patch.zip | awk '{print $1}')" = \
  "$(v21_get PATCH_PLAIN_SHA256)"

mkdir v21-patch
if command -v ditto >/dev/null 2>&1; then
  ditto -x -k v21-patch.zip v21-patch
else
  unzip -q v21-patch.zip -d v21-patch
fi
PATCHER=v21-patch/aspire-v21-patcher/patch.py
test -f "$PATCHER"
test "$(shasum -a 256 "$PATCHER" | awk '{print $1}')" = \
  "$(v21_get PATCHER_SHA256)"
python3 -m py_compile "$PATCHER"

mkdir -p "$(dirname "$RECEIPT_PATH")"
python3 "$PATCHER" "$RUN_PATH" "$BROWSER_PATH" "$RECEIPT_PATH"

OUTPUT_RUN_SHA="$(shasum -a 256 "$RUN_PATH" | awk '{print $1}')"
OUTPUT_BROWSER_SHA="$(shasum -a 256 "$BROWSER_PATH" | awk '{print $1}')"
test "$OUTPUT_RUN_SHA" = "$(v21_get OUTPUT_RUN_SHA256)"
test "$OUTPUT_BROWSER_SHA" = "$(v21_get OUTPUT_BROWSER_SHA256)"
bash -n "$RUN_PATH"
node --check "$BROWSER_PATH"
python3 -m json.tool "$RECEIPT_PATH" >/dev/null

if grep -Fq -- '--ignore-certificate-errors' "$RUN_PATH" "$BROWSER_PATH"; then
  echo 'forbidden Chromium certificate bypass remains' >&2
  exit 31
fi
if grep -Fq 'ignoreHTTPSErrors: true' "$RUN_PATH" "$BROWSER_PATH"; then
  echo 'forbidden Playwright certificate bypass remains' >&2
  exit 32
fi
if grep -Fq 'env.DASHBOARD_PORT' "$BROWSER_PATH"; then
  echo 'browser still receives injected Dashboard port' >&2
  exit 33
fi
if grep -Eq '(^|[[:space:]])DASHBOARD_PORT=' "$RUN_PATH"; then
  echo 'run harness still exports injected Dashboard port' >&2
  exit 34
fi
grep -Fq 'captured_dashboard_port' "$RUN_PATH"
grep -Fq 'dashboardPortDiscoveredFromReferrer' "$BROWSER_PATH"
grep -Fq 'discoveredDashboardPortMatchesLoginOrigin' "$BROWSER_PATH"
grep -Fq 'security add-trusted-cert' "$RUN_PATH"
grep -Fq 'EXPORTED_PRIVATE_KEY_REMOVED=PASS' "$RUN_PATH"

printf 'V21_INPUT_RUN_SHA256=%s\n' "$INPUT_RUN_SHA"
printf 'V21_INPUT_BROWSER_SHA256=%s\n' "$INPUT_BROWSER_SHA"
printf 'V21_OUTPUT_RUN_SHA256=%s\n' "$OUTPUT_RUN_SHA"
printf 'V21_OUTPUT_BROWSER_SHA256=%s\n' "$OUTPUT_BROWSER_SHA"
echo V21_APPLY=PASS
