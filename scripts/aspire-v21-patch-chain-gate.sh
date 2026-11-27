#!/usr/bin/env bash
set -euo pipefail

: "${WRAPPING_KEY_B64:?WRAPPING_KEY_B64 is required}"

SOURCE=scripts/aspire-v20-patch-chain-gate.sh
GENERATED=.aspire-v21-patch-chain.generated.sh

test -f "$SOURCE"
test "$(sha256sum "$SOURCE" | awk '{print $1}')" = \
  6698f27233f97063b1d391627cd12f92295a1d3d95789f0cec208da12fb8bdb9

cleanup_wrapper() {
  rm -f "$GENERATED"
}
trap cleanup_wrapper EXIT

python3 - "$SOURCE" "$GENERATED" <<'PY_GENERATE'
from pathlib import Path
import sys

source_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
source = source_path.read_text()

cleanup_old = '''    v20.enc.b64.norm v20.enc v20.key.enc v20.key v20.zip v20 \\
    patched-v11 patched-v13 \\
    v16-receipt.json v18-receipt.json v20-receipt.json
'''
cleanup_new = '''    v20.enc.b64.norm v20.enc v20.key.enc v20.key v20.zip v20 \\
    v21.enc.b64.norm v21.enc v21.key.enc v21.key v21.zip v21 \\
    patched-v11 patched-v13 \\
    v16-receipt.json v18-receipt.json v20-receipt.json v21-receipt.json
'''
if source.count(cleanup_old) != 1:
    raise SystemExit(f'cleanup anchor count={source.count(cleanup_old)}')
source = source.replace(cleanup_old, cleanup_new, 1)

helper_old = '''v20_get() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \\
    sealed/aspire-v20-trusted-yarp-patcher.metadata
}
'''
helper_new = helper_old + '''v21_get() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \\
    sealed/aspire-v21-natural-discovery-patcher.metadata
}
'''
if source.count(helper_old) != 1:
    raise SystemExit(f'helper anchor count={source.count(helper_old)}')
source = source.replace(helper_old, helper_new, 1)

post_v20_old = '''test "$(sha256sum "$RUN" | awk '{print $1}')" = "$(v20_get OUTPUT_RUN_SHA256)"
test "$(sha256sum "$BROWSER" | awk '{print $1}')" = "$(v20_get OUTPUT_BROWSER_SHA256)"
bash -n "$RUN"
node --check "$BROWSER"
python3 -m json.tool v16-receipt.json >/dev/null
python3 -m json.tool v18-receipt.json >/dev/null
python3 -m json.tool v20-receipt.json >/dev/null
'''
post_v20_new = '''test "$(sha256sum "$RUN" | awk '{print $1}')" = "$(v20_get OUTPUT_RUN_SHA256)"
test "$(sha256sum "$BROWSER" | awk '{print $1}')" = "$(v20_get OUTPUT_BROWSER_SHA256)"

# Apply the sealed v21 natural-discovery/noninteractive-trust transformation.
test "$(sha256sum scripts/aspire-v21-apply.sh | awk '{print $1}')" = \\
  22051d15451929bb6f28a2efd491978c3855d24dfcd62881aef023fdf56c0b9b
bash scripts/aspire-v21-apply.sh "$RUN" "$BROWSER" v21-receipt.json

test "$(sha256sum "$RUN" | awk '{print $1}')" = "$(v21_get OUTPUT_RUN_SHA256)"
test "$(sha256sum "$BROWSER" | awk '{print $1}')" = "$(v21_get OUTPUT_BROWSER_SHA256)"
bash -n "$RUN"
node --check "$BROWSER"
python3 -m json.tool v16-receipt.json >/dev/null
python3 -m json.tool v18-receipt.json >/dev/null
python3 -m json.tool v20-receipt.json >/dev/null
python3 -m json.tool v21-receipt.json >/dev/null
'''
if source.count(post_v20_old) != 1:
    raise SystemExit(f'post-v20 anchor count={source.count(post_v20_old)}')
source = source.replace(post_v20_old, post_v20_new, 1)

terminal_old = '''printf 'FINAL_RUN_SHA256=%s\\n' "$(sha256sum "$RUN" | awk '{print $1}')"
printf 'FINAL_BROWSER_SHA256=%s\\n' "$(sha256sum "$BROWSER" | awk '{print $1}')"
echo V20_PATCH_CHAIN_GATE=PASS
'''
terminal_new = '''if grep -Fq 'env.DASHBOARD_PORT' "$BROWSER"; then
  echo 'injected Dashboard port remains after v21 chain' >&2
  exit 41
fi
if grep -Eq '(^|[[:space:]])DASHBOARD_PORT=' "$RUN"; then
  echo 'Dashboard-port environment injection remains after v21 chain' >&2
  exit 42
fi
grep -Fq 'dashboardPortDiscoveredFromReferrer' "$BROWSER"
grep -Fq 'discoveredDashboardPortMatchesLoginOrigin' "$BROWSER"
grep -Fq 'captured_dashboard_port' "$RUN"
grep -Fq 'security add-trusted-cert' "$RUN"
grep -Fq 'EXPORTED_PRIVATE_KEY_REMOVED=PASS' "$RUN"
printf 'FINAL_RUN_SHA256=%s\\n' "$(sha256sum "$RUN" | awk '{print $1}')"
printf 'FINAL_BROWSER_SHA256=%s\\n' "$(sha256sum "$BROWSER" | awk '{print $1}')"
echo V21_PATCH_CHAIN_GATE=PASS
'''
if source.count(terminal_old) != 1:
    raise SystemExit(f'terminal anchor count={source.count(terminal_old)}')
source = source.replace(terminal_old, terminal_new, 1)

output_path.write_text(source)
PY_GENERATE

test "$(sha256sum "$GENERATED" | awk '{print $1}')" = \
  848c6172d396b39493a2ec90651f31ddb19da7fb74f4d3fb16461072d422019d
bash -n "$GENERATED"
chmod 700 "$GENERATED" scripts/aspire-v21-apply.sh
WRAPPING_KEY_B64="$WRAPPING_KEY_B64" "$GENERATED"
