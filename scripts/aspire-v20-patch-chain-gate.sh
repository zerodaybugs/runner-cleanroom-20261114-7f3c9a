#!/usr/bin/env bash
set -euo pipefail

: "${WRAPPING_KEY_B64:?WRAPPING_KEY_B64 is required}"

meta_get() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
    sealed/aspire-macos-matrix-v10-selfcontained-overlay.metadata
}
v13_get() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
    sealed/aspire-v13-combined-patch.metadata
}
v20_get() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
    sealed/aspire-v20-trusted-yarp-patcher.metadata
}

cleanup() {
  rm -rf \
    wrapping.key private.pem \
    overlay.enc.b64.norm overlay.enc overlay.key.enc overlay.key overlay.zip overlay \
    v13.enc.b64.norm v13.enc v13.key.enc v13.key v13.zip v13 \
    v20.enc.b64.norm v20.enc v20.key.enc v20.key v20.zip v20 \
    patched-v11 patched-v13 \
    v16-receipt.json v18-receipt.json v20-receipt.json
}
trap cleanup EXIT

printf '%s' "$WRAPPING_KEY_B64" | openssl base64 -d -A > wrapping.key
test "$(wc -c < wrapping.key | tr -d ' ')" = 32
WRAP_KEY_HEX="$(od -An -tx1 -v wrapping.key | tr -d ' \n')"
openssl enc -d -aes-256-cbc \
  -K "$WRAP_KEY_HEX" \
  -iv "$(tr -d '\r\n ' < bootstrap/private.iv.hex)" \
  -in bootstrap/private.pem.enc \
  -out private.pem

# Reconstruct the verified v10 base overlay.
tr -d '\r\n ' < sealed/aspire-macos-matrix-v10-selfcontained-overlay.enc.b64 > overlay.enc.b64.norm
test "$(sha256sum overlay.enc.b64.norm | awk '{print $1}')" = "$(meta_get OVERLAY_B64_NORMALIZED_SHA256)"
openssl base64 -d -A -in overlay.enc.b64.norm -out overlay.enc
test "$(sha256sum overlay.enc | awk '{print $1}')" = "$(meta_get OVERLAY_CIPHER_SHA256)"
tr -d '\r\n ' < sealed/aspire-macos-matrix-v10-selfcontained-overlay.key.enc.b64 | \
  openssl base64 -d -A > overlay.key.enc
test "$(sha256sum overlay.key.enc | awk '{print $1}')" = "$(meta_get OVERLAY_KEY_CIPHER_SHA256)"
openssl pkeyutl -decrypt \
  -inkey private.pem \
  -in overlay.key.enc \
  -out overlay.key \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256
test "$(wc -c < overlay.key | tr -d ' ')" = 32
OVERLAY_KEY_HEX="$(od -An -tx1 -v overlay.key | tr -d ' \n')"
openssl enc -d -aes-256-cbc \
  -K "$OVERLAY_KEY_HEX" \
  -iv "$(meta_get OVERLAY_IV_HEX)" \
  -in overlay.enc \
  -out overlay.zip
test "$(sha256sum overlay.zip | awk '{print $1}')" = "$(meta_get OVERLAY_PLAIN_SHA256)"
mkdir overlay
unzip -q overlay.zip -d overlay
BASE=overlay/aspire-macos-matrix-v10-selfcontained
test "$(sha256sum "$BASE/run.sh" | awk '{print $1}')" = "$(meta_get RUN_SH_SHA256)"
test "$(sha256sum "$BASE/browser.js" | awk '{print $1}')" = "$(meta_get BROWSER_JS_SHA256)"

# Apply and verify the canonical v13 chain.
cat sealed/aspire-v13-combined-patch.enc.b64.part-* | tr -d '\r\n ' > v13.enc.b64.norm
test "$(sha256sum v13.enc.b64.norm | awk '{print $1}')" = "$(v13_get PATCH_B64_NORMALIZED_SHA256)"
openssl base64 -d -A -in v13.enc.b64.norm -out v13.enc
test "$(sha256sum v13.enc | awk '{print $1}')" = "$(v13_get PATCH_CIPHER_SHA256)"
tr -d '\r\n ' < sealed/aspire-v13-combined-patch.key.enc.b64 | \
  openssl base64 -d -A > v13.key.enc
test "$(sha256sum v13.key.enc | awk '{print $1}')" = "$(v13_get PATCH_KEY_CIPHER_SHA256)"
openssl pkeyutl -decrypt \
  -inkey private.pem \
  -in v13.key.enc \
  -out v13.key \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256
test "$(wc -c < v13.key | tr -d ' ')" = 32
V13_KEY_HEX="$(od -An -tx1 -v v13.key | tr -d ' \n')"
openssl enc -d -aes-256-cbc \
  -K "$V13_KEY_HEX" \
  -iv "$(v13_get PATCH_IV_HEX)" \
  -in v13.enc \
  -out v13.zip
test "$(sha256sum v13.zip | awk '{print $1}')" = "$(v13_get PATCH_PLAIN_SHA256)"
mkdir v13
unzip -q v13.zip -d v13
V13_ROOT=v13/aspire-v13-combined-patch
PATCH_V11="$V13_ROOT/patch-v11.py"
PATCH_V13="$V13_ROOT/patch-v13.py"
test "$(sha256sum "$PATCH_V11" | awk '{print $1}')" = "$(v13_get PATCH_V11_PY_SHA256)"
test "$(sha256sum "$PATCH_V13" | awk '{print $1}')" = "$(v13_get PATCH_V13_PY_SHA256)"
python3 "$PATCH_V11" "$BASE" patched-v11
python3 "$PATCH_V13" patched-v11 patched-v13
RUN=patched-v13/run.sh
BROWSER=patched-v13/browser.js
test "$(sha256sum "$RUN" | awk '{print $1}')" = "$(v13_get FINAL_RUN_SHA256)"
test "$(sha256sum "$BROWSER" | awk '{print $1}')" = "$(v13_get FINAL_BROWSER_SHA256)"

# Apply the verified v16 and v18 harness transformations.
test "$(sha256sum scripts/aspire-v16-final-harness.py | awk '{print $1}')" = \
  02142f2ef0706b36be7d024b09ba84857bb7580da919a5c49cc19f2b174973e6
test "$(sha256sum scripts/aspire-v18-direct-apphost-harness.py | awk '{print $1}')" = \
  195bec386f284ed8456002d1a81637e46a42c5cc67213c10162864744cc065f1
python3 scripts/aspire-v16-final-harness.py "$RUN" v16-receipt.json
test "$(sha256sum "$RUN" | awk '{print $1}')" = \
  ab129da6a4cfcaff8b4001722b3f5220d0ea9d7be6e225a921ebfba776ffb2b1
python3 scripts/aspire-v18-direct-apphost-harness.py "$RUN" v18-receipt.json
test "$(sha256sum "$RUN" | awk '{print $1}')" = "$(v20_get INPUT_RUN_SHA256)"
test "$(sha256sum "$BROWSER" | awk '{print $1}')" = "$(v20_get INPUT_BROWSER_SHA256)"

# Apply the consolidated trusted-YARP v20 transformation.
cat sealed/aspire-v20-trusted-yarp-patcher.enc.b64.part-* | tr -d '\r\n ' > v20.enc.b64.norm
test "$(sha256sum v20.enc.b64.norm | awk '{print $1}')" = "$(v20_get PATCH_B64_NORMALIZED_SHA256)"
openssl base64 -d -A -in v20.enc.b64.norm -out v20.enc
test "$(sha256sum v20.enc | awk '{print $1}')" = "$(v20_get PATCH_CIPHER_SHA256)"
tr -d '\r\n ' < sealed/aspire-v20-trusted-yarp-patcher.key.enc.b64 | \
  openssl base64 -d -A > v20.key.enc
test "$(sha256sum v20.key.enc | awk '{print $1}')" = "$(v20_get PATCH_KEY_CIPHER_SHA256)"
openssl pkeyutl -decrypt \
  -inkey private.pem \
  -in v20.key.enc \
  -out v20.key \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256
test "$(wc -c < v20.key | tr -d ' ')" = 32
V20_KEY_HEX="$(od -An -tx1 -v v20.key | tr -d ' \n')"
openssl enc -d -aes-256-cbc \
  -K "$V20_KEY_HEX" \
  -iv "$(v20_get PATCH_IV_HEX)" \
  -in v20.enc \
  -out v20.zip
test "$(sha256sum v20.zip | awk '{print $1}')" = "$(v20_get PATCH_PLAIN_SHA256)"
mkdir v20
unzip -q v20.zip -d v20
PATCHER=v20/aspire-v20-patcher/patch.py
test "$(sha256sum "$PATCHER" | awk '{print $1}')" = "$(v20_get PATCHER_SHA256)"
python3 -m py_compile "$PATCHER"
python3 "$PATCHER" "$RUN" "$BROWSER" v20-receipt.json

test "$(sha256sum "$RUN" | awk '{print $1}')" = "$(v20_get OUTPUT_RUN_SHA256)"
test "$(sha256sum "$BROWSER" | awk '{print $1}')" = "$(v20_get OUTPUT_BROWSER_SHA256)"
bash -n "$RUN"
node --check "$BROWSER"
python3 -m json.tool v16-receipt.json >/dev/null
python3 -m json.tool v18-receipt.json >/dev/null
python3 -m json.tool v20-receipt.json >/dev/null

# Trust bypasses are forbidden in the final harness.
if grep -Fq -- '--ignore-certificate-errors' "$RUN" "$BROWSER"; then
  echo 'forbidden Chromium certificate bypass remains' >&2
  exit 31
fi
if grep -Fq 'ignoreHTTPSErrors: true' "$RUN" "$BROWSER"; then
  echo 'forbidden Playwright certificate bypass remains' >&2
  exit 32
fi

printf 'FINAL_RUN_SHA256=%s\n' "$(sha256sum "$RUN" | awk '{print $1}')"
printf 'FINAL_BROWSER_SHA256=%s\n' "$(sha256sum "$BROWSER" | awk '{print $1}')"
echo V20_PATCH_CHAIN_GATE=PASS
