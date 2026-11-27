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

v20_get() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
    sealed/aspire-v20-trusted-yarp-patcher.metadata
}

cleanup_v20() {
  rm -rf \
    v20-patch.enc.b64.norm v20-patch.enc \
    v20-patch.key.enc v20-patch.runtime.key \
    v20-patch.zip v20-patch
}
trap cleanup_v20 EXIT

INPUT_RUN_SHA="$(shasum -a 256 "$RUN_PATH" | awk '{print $1}')"
INPUT_BROWSER_SHA="$(shasum -a 256 "$BROWSER_PATH" | awk '{print $1}')"
test "$INPUT_RUN_SHA" = "$(v20_get INPUT_RUN_SHA256)"
test "$INPUT_BROWSER_SHA" = "$(v20_get INPUT_BROWSER_SHA256)"

cat sealed/aspire-v20-trusted-yarp-patcher.enc.b64.part-* | tr -d '\r\n ' > v20-patch.enc.b64.norm
test "$(shasum -a 256 v20-patch.enc.b64.norm | awk '{print $1}')" = \
  "$(v20_get PATCH_B64_NORMALIZED_SHA256)"
openssl base64 -d -A -in v20-patch.enc.b64.norm -out v20-patch.enc
test "$(shasum -a 256 v20-patch.enc | awk '{print $1}')" = \
  "$(v20_get PATCH_CIPHER_SHA256)"

tr -d '\r\n ' < sealed/aspire-v20-trusted-yarp-patcher.key.enc.b64 | \
  openssl base64 -d -A > v20-patch.key.enc
test "$(shasum -a 256 v20-patch.key.enc | awk '{print $1}')" = \
  "$(v20_get PATCH_KEY_CIPHER_SHA256)"
openssl pkeyutl -decrypt \
  -inkey private.pem \
  -in v20-patch.key.enc \
  -out v20-patch.runtime.key \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256
test "$(wc -c < v20-patch.runtime.key | tr -d ' ')" = 32

V20_KEY_HEX="$(od -An -tx1 -v v20-patch.runtime.key | tr -d ' \n')"
V20_IV_HEX="$(v20_get PATCH_IV_HEX)"
test "${#V20_IV_HEX}" = 32
openssl enc -d -aes-256-cbc \
  -K "$V20_KEY_HEX" \
  -iv "$V20_IV_HEX" \
  -in v20-patch.enc \
  -out v20-patch.zip
test "$(shasum -a 256 v20-patch.zip | awk '{print $1}')" = \
  "$(v20_get PATCH_PLAIN_SHA256)"

mkdir v20-patch
ditto -x -k v20-patch.zip v20-patch
PATCHER=v20-patch/aspire-v20-patcher/patch.py
test -f "$PATCHER"
test "$(shasum -a 256 "$PATCHER" | awk '{print $1}')" = \
  "$(v20_get PATCHER_SHA256)"
python3 -m py_compile "$PATCHER"

mkdir -p "$(dirname "$RECEIPT_PATH")"
python3 "$PATCHER" "$RUN_PATH" "$BROWSER_PATH" "$RECEIPT_PATH"

OUTPUT_RUN_SHA="$(shasum -a 256 "$RUN_PATH" | awk '{print $1}')"
OUTPUT_BROWSER_SHA="$(shasum -a 256 "$BROWSER_PATH" | awk '{print $1}')"
test "$OUTPUT_RUN_SHA" = "$(v20_get OUTPUT_RUN_SHA256)"
test "$OUTPUT_BROWSER_SHA" = "$(v20_get OUTPUT_BROWSER_SHA256)"
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

printf 'V20_INPUT_RUN_SHA256=%s\n' "$INPUT_RUN_SHA"
printf 'V20_INPUT_BROWSER_SHA256=%s\n' "$INPUT_BROWSER_SHA"
printf 'V20_OUTPUT_RUN_SHA256=%s\n' "$OUTPUT_RUN_SHA"
printf 'V20_OUTPUT_BROWSER_SHA256=%s\n' "$OUTPUT_BROWSER_SHA"
echo V20_APPLY=PASS
