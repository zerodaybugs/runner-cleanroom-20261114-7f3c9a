#!/usr/bin/env bash
set -euo pipefail
test -n "$WRAPPING_KEY_B64"

meta_get() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' sealed/aspire-macos-matrix-v10-selfcontained-overlay.metadata
}
patch_meta_get() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' sealed/aspire-v13-combined-patch.metadata
}

printf '%s' "$WRAPPING_KEY_B64" | openssl base64 -d -A > wrapping.key
test "$(wc -c < wrapping.key | tr -d ' ')" = "32"
WRAP_KEY_HEX="$(od -An -tx1 -v wrapping.key | tr -d ' \n')"
openssl enc -d -aes-256-cbc -K "$WRAP_KEY_HEX" -iv "$(tr -d '\r\n ' < bootstrap/private.iv.hex)" -in bootstrap/private.pem.enc -out private.pem

tr -d '\r\n ' < sealed/aspire-macos-matrix-v2.key.enc.b64 | openssl base64 -d -A > payload.key.enc
test "$(shasum -a 256 payload.key.enc | awk '{print $1}')" = "be22571a034deff9daca1291cecadcdddfd98e79f49ee4e4cd548eb5bff2b2ad"
openssl pkeyutl -decrypt -inkey private.pem -in payload.key.enc -out matrix.runtime.key -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256
test "$(wc -c < matrix.runtime.key | tr -d ' ')" = "32"
EVIDENCE_DIR=evidence-aspire120006-macos-v13-ui-lifecycle
mkdir -p "$EVIDENCE_DIR"

tr -d '\r\n ' < sealed/aspire-macos-matrix-v2.enc.b64 | openssl base64 -d -A > payload.enc
test "$(shasum -a 256 payload.enc | awk '{print $1}')" = "1d981b7a24d7f1d15d75782c658e122a87bab89e512f6dfa775d5827d0545f24"
KEY_HEX="$(od -An -tx1 -v matrix.runtime.key | tr -d ' \n')"
openssl enc -d -aes-256-cbc -K "$KEY_HEX" -iv "206224599d55f53eba5616f78531addb" -in payload.enc -out payload.zip
test "$(shasum -a 256 payload.zip | awk '{print $1}')" = "ba640f7ae180b198351ff27f579158fabad7a7057261133bc5888dfe2e50a9f9"

mkdir -p private-payload
ditto -x -k payload.zip private-payload

tr -d '\r\n ' < sealed/aspire-macos-matrix-v10-selfcontained-overlay.enc.b64 > overlay.enc.b64.norm
test "$(shasum -a 256 overlay.enc.b64.norm | awk '{print $1}')" = "$(meta_get OVERLAY_B64_NORMALIZED_SHA256)"
openssl base64 -d -A -in overlay.enc.b64.norm -out overlay.enc
test "$(shasum -a 256 overlay.enc | awk '{print $1}')" = "$(meta_get OVERLAY_CIPHER_SHA256)"

tr -d '\r\n ' < sealed/aspire-macos-matrix-v10-selfcontained-overlay.key.enc.b64 | openssl base64 -d -A > overlay.key.enc
test "$(shasum -a 256 overlay.key.enc | awk '{print $1}')" = "$(meta_get OVERLAY_KEY_CIPHER_SHA256)"
openssl pkeyutl -decrypt -inkey private.pem -in overlay.key.enc -out overlay.runtime.key -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256
test "$(wc -c < overlay.runtime.key | tr -d ' ')" = "32"

OVERLAY_KEY_HEX="$(od -An -tx1 -v overlay.runtime.key | tr -d ' \n')"
OVERLAY_IV_HEX="$(meta_get OVERLAY_IV_HEX)"
test "${#OVERLAY_IV_HEX}" = "32"
openssl enc -d -aes-256-cbc -K "$OVERLAY_KEY_HEX" -iv "$OVERLAY_IV_HEX" -in overlay.enc -out overlay.zip
test "$(shasum -a 256 overlay.zip | awk '{print $1}')" = "$(meta_get OVERLAY_PLAIN_SHA256)"
test "$(unzip -Z1 overlay.zip | sort | tr '\n' '|')" = "aspire-macos-matrix-v10-selfcontained/browser.js|aspire-macos-matrix-v10-selfcontained/run.sh|"

mkdir -p overlay
ditto -x -k overlay.zip overlay
test "$(shasum -a 256 overlay/aspire-macos-matrix-v10-selfcontained/run.sh | awk '{print $1}')" = "$(meta_get RUN_SH_SHA256)"
test "$(shasum -a 256 overlay/aspire-macos-matrix-v10-selfcontained/browser.js | awk '{print $1}')" = "$(meta_get BROWSER_JS_SHA256)"

cat sealed/aspire-v13-combined-patch.enc.b64.part-* | tr -d '\r\n ' > patch.enc.b64.norm
test "$(shasum -a 256 patch.enc.b64.norm | awk '{print $1}')" = "$(patch_meta_get PATCH_B64_NORMALIZED_SHA256)"
openssl base64 -d -A -in patch.enc.b64.norm -out patch.enc
test "$(shasum -a 256 patch.enc | awk '{print $1}')" = "$(patch_meta_get PATCH_CIPHER_SHA256)"

tr -d '\r\n ' < sealed/aspire-v13-combined-patch.key.enc.b64 | openssl base64 -d -A > patch.key.enc
test "$(shasum -a 256 patch.key.enc | awk '{print $1}')" = "$(patch_meta_get PATCH_KEY_CIPHER_SHA256)"
openssl pkeyutl -decrypt -inkey private.pem -in patch.key.enc -out patch.runtime.key -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256
test "$(wc -c < patch.runtime.key | tr -d ' ')" = "32"

PATCH_KEY_HEX="$(od -An -tx1 -v patch.runtime.key | tr -d ' \n')"
PATCH_IV_HEX="$(patch_meta_get PATCH_IV_HEX)"
test "${#PATCH_IV_HEX}" = "32"
openssl enc -d -aes-256-cbc -K "$PATCH_KEY_HEX" -iv "$PATCH_IV_HEX" -in patch.enc -out patch.zip
test "$(shasum -a 256 patch.zip | awk '{print $1}')" = "$(patch_meta_get PATCH_PLAIN_SHA256)"
test "$(unzip -Z1 patch.zip | sort | tr '\n' '|')" = "aspire-v13-combined-patch/PATCH_CHAIN.json|aspire-v13-combined-patch/patch-v11.py|aspire-v13-combined-patch/patch-v13.py|"
mkdir -p patch
ditto -x -k patch.zip patch
PATCH_ROOT=patch/aspire-v13-combined-patch
PATCH_V11="$PATCH_ROOT/patch-v11.py"
PATCH_V13="$PATCH_ROOT/patch-v13.py"
PATCH_CHAIN="$PATCH_ROOT/PATCH_CHAIN.json"
test "$(shasum -a 256 "$PATCH_V11" | awk '{print $1}')" = "$(patch_meta_get PATCH_V11_PY_SHA256)"
test "$(shasum -a 256 "$PATCH_V13" | awk '{print $1}')" = "$(patch_meta_get PATCH_V13_PY_SHA256)"
test "$(shasum -a 256 "$PATCH_CHAIN" | awk '{print $1}')" = "$(patch_meta_get PATCH_CHAIN_SHA256)"

set +e
python3 "$PATCH_V11" overlay/aspire-macos-matrix-v10-selfcontained patched-v11 > "$EVIDENCE_DIR/patch-v11.stdout" 2> "$EVIDENCE_DIR/patch-v11.stderr"
PATCH_V11_RC=$?
set -e
printf 'PATCH_V11_RC=%s\n' "$PATCH_V11_RC" > "$EVIDENCE_DIR/patch-v11-status.txt"
if [[ "$PATCH_V11_RC" -ne 0 ]]; then
  echo "matrix_rc=97" >> "$GITHUB_OUTPUT"
  exit 97
fi
test "$(shasum -a 256 patched-v11/run.sh | awk '{print $1}')" = "$(patch_meta_get V11_RUN_SHA256)"
test "$(shasum -a 256 patched-v11/browser.js | awk '{print $1}')" = "$(patch_meta_get V11_BROWSER_SHA256)"

set +e
python3 "$PATCH_V13" patched-v11 patched-v13 > "$EVIDENCE_DIR/patch-v13.stdout" 2> "$EVIDENCE_DIR/patch-v13.stderr"
PATCH_V13_RC=$?
set -e
printf 'PATCH_V13_RC=%s\n' "$PATCH_V13_RC" > "$EVIDENCE_DIR/patch-v13-status.txt"
if [[ "$PATCH_V13_RC" -ne 0 ]]; then
  echo "matrix_rc=98" >> "$GITHUB_OUTPUT"
  exit 98
fi

PATCHED_RUN=patched-v13/run.sh
PATCHED_BROWSER=patched-v13/browser.js
PATCH_MANIFEST=patched-v13/V13_PATCH_MANIFEST.json
test -f "$PATCH_MANIFEST"
PATCHED_RUN_SHA="$(shasum -a 256 "$PATCHED_RUN" | awk '{print $1}')"
PATCHED_BROWSER_SHA="$(shasum -a 256 "$PATCHED_BROWSER" | awk '{print $1}')"
test "$PATCHED_RUN_SHA" = "$(patch_meta_get FINAL_RUN_SHA256)"
test "$PATCHED_BROWSER_SHA" = "$(patch_meta_get FINAL_BROWSER_SHA256)"
python3 - "$PATCH_CHAIN" "$PATCH_MANIFEST" "$PATCHED_RUN_SHA" "$PATCHED_BROWSER_SHA" <<'PY_MANIFEST'
import json,sys
chain_path,manifest_path,run_sha,browser_sha=sys.argv[1:]
chain=json.load(open(chain_path))
manifest=json.load(open(manifest_path))
assert chain['base_v10_run_sha256']=='05e724c967e91f88a5c58e4a3966f70f683517c9861841894934d86f22fab1db'
assert chain['base_v10_browser_sha256']=='d6be883d27624841150cdc3d9bddd953566cae2d2d41f46e6fe47c29e2cfe6d2'
assert chain['v11_run_sha256']=='356f1088f3d417ef30c40ca6e7a7985f48df6f5a1847ba3a108334e78960a9cc'
assert chain['v11_browser_sha256']=='616a1616a44d50a966f9f9469cd5d885d02ec92cd99c109054043c9a18540c90'
assert chain['final_run_sha256']==run_sha
assert chain['final_browser_sha256']==browser_sha
assert manifest['base_run_sha256']==chain['v11_run_sha256']
assert manifest['base_browser_sha256']==chain['v11_browser_sha256']
assert manifest['patched_run_sha256']==run_sha
assert manifest['patched_browser_sha256']==browser_sha
assert manifest['synthetic_privileged_command_removed'] is True
assert manifest['sink']=='stock Aspire Dashboard Stop/Start lifecycle commands'
assert manifest['navigation']=='stock Dashboard resource row to explicit HTTPS endpoint link'
PY_MANIFEST
bash -n "$PATCHED_RUN"
node --check "$PATCHED_BROWSER"
cp "$PATCH_CHAIN" "$EVIDENCE_DIR/PATCH_CHAIN.json"
cp "$PATCH_MANIFEST" "$EVIDENCE_DIR/V13_PATCH_MANIFEST.json"
printf '%s  run.sh\n%s  browser.js\n' "$PATCHED_RUN_SHA" "$PATCHED_BROWSER_SHA" > "$EVIDENCE_DIR/patched-hashes.txt"
echo "patched_run_sha=$PATCHED_RUN_SHA" >> "$GITHUB_OUTPUT"
echo "patched_browser_sha=$PATCHED_BROWSER_SHA" >> "$GITHUB_OUTPUT"

cp "$PATCHED_RUN" private-payload/aspire-macos-matrix-v2/run.sh
cp "$PATCHED_BROWSER" private-payload/aspire-macos-matrix-v2/browser.js
chmod 700 private-payload/aspire-macos-matrix-v2/run.sh

set +e
bash -x private-payload/aspire-macos-matrix-v2/run.sh > "$EVIDENCE_DIR/bootstrap-trace.log" 2>&1
MATRIX_RC=$?
set -e
printf 'MATRIX_RC=%s\n' "$MATRIX_RC" > "$EVIDENCE_DIR/bootstrap-status.txt"
echo "matrix_rc=$MATRIX_RC" >> "$GITHUB_OUTPUT"
exit "$MATRIX_RC"
