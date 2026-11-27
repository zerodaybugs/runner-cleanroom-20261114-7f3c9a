#!/usr/bin/env python3
import hashlib
import json
import pathlib
import re
import sys

if len(sys.argv) not in (2, 3):
    raise SystemExit(f"usage: {sys.argv[0]} RUN_SH [RECEIPT_JSON]")

run_path = pathlib.Path(sys.argv[1])
receipt_path = pathlib.Path(sys.argv[2]) if len(sys.argv) == 3 else None
source = run_path.read_text()
before = hashlib.sha256(source.encode()).hexdigest()
changes = []

# Replace the CI-only PTY wrapper with direct execution of the already-built AppHost.
# This leaves product packages, model construction, browser exploit logic, and assertions unchanged.
launch_pattern = re.compile(
    r'(?ms)^  local pty_runner="\$out/pty-runner\.py"\n'
    r'  cat > "\$pty_runner" <<\'PY_PTY_RUNNER\'\n'
    r'.*?'
    r'^PY_PTY_RUNNER\n'
    r'  chmod 700 "\$pty_runner"\n'
    r'  python3 "\$pty_runner" "\$log" dotnet run --no-build --launch-profile https &\n'
    r'  local apphost_pid=\$!\n'
    r'  ACTIVE_APPHOST_PID="\$apphost_pid"\n'
)
matches = list(launch_pattern.finditer(source))
if len(matches) != 1:
    raise SystemExit(f"PTY direct-launch marker count={len(matches)}")

direct_launch = r'''  local browser_token apphost_dll
  browser_token="$(openssl rand -hex 16)"
  apphost_dll="$dir/AppHost/bin/Debug/$target_framework/AppHost.dll"
  test -f "$apphost_dll" || { echo APPHOST_DLL_MISSING > "$out/status.txt"; return 1; }
  printf '%s\n' "$(sha256sum "$apphost_dll" | awk '{print $1}')" > "$out/apphost-dll.sha256"
  ASPNETCORE_ENVIRONMENT=Development \
  DOTNET_ENVIRONMENT=Development \
  ASPNETCORE_URLS="https://localhost:$dash;http://localhost:$apphttp" \
  ASPIRE_DASHBOARD_OTLP_ENDPOINT_URL="https://localhost:$otlp" \
  ASPIRE_RESOURCE_SERVICE_ENDPOINT_URL="https://localhost:$resource" \
  ASPIRE_DASHBOARD_FRONTEND_BROWSERTOKEN="$browser_token" \
  dotnet "$apphost_dll" > "$log" 2>&1 &
  local apphost_pid=$!
  ACTIVE_APPHOST_PID="$apphost_pid"
'''
source, count = launch_pattern.subn(lambda _match: direct_launch, source, count=1)
if count != 1:
    raise SystemExit("direct AppHost substitution failed")
changes.append("launch the built AppHost directly instead of through Aspire CLI/PTTY")

old_login = r'''  local login=''
  for i in $(seq 1 180); do
    login=$(grep -Eo 'https://localhost:[0-9]+/login\?t=[-A-Za-z0-9_]+' "$log" | tail -1 || true)
    [[ -n "$login" ]] && break
    grep -q 'Unhandled exception' "$log" && break
    sleep 1
  done
'''
new_login = r'''  local login="https://localhost:$dash/login?t=$browser_token"
  local dashboard_ready=0
  for i in $(seq 1 180); do
    if curl -kfsS --connect-timeout 1 --max-time 2 "https://localhost:$dash/" >/dev/null 2>&1; then
      dashboard_ready=1
      break
    fi
    kill -0 "$apphost_pid" 2>/dev/null || break
    sleep 1
  done
  python3 - "$out/login-token-shape.json" "$login" "$dashboard_ready" <<'PY_LOGIN_RECEIPT'
import hashlib, json, sys, urllib.parse
out, url, ready = sys.argv[1:]
parsed = urllib.parse.urlsplit(url)
token = urllib.parse.parse_qs(parsed.query).get('t', [''])[0]
json.dump({
    'loginUrlPresent': bool(url),
    'dashboardHttpsReady': ready == '1',
    'scheme': parsed.scheme,
    'host': parsed.hostname,
    'port': parsed.port,
    'path': parsed.path,
    'tokenLength': len(token),
    'tokenIsLowerHex32': len(token) == 32 and all(c in '0123456789abcdef' for c in token),
    'loginUrlSha256': hashlib.sha256(url.encode()).hexdigest(),
}, open(out, 'w'), indent=2, sort_keys=True)
PY_LOGIN_RECEIPT
'''
if source.count(old_login) != 1:
    raise SystemExit(f"login loop marker count={source.count(old_login)}")
source = source.replace(old_login, new_login, 1)
changes.append("use an explicit authenticated Dashboard token and HTTPS readiness probe")

old_gate = r'''  if [[ -z "$login" ]] || ! kill -0 "$apphost_pid" 2>/dev/null; then
'''
new_gate = r'''  if [[ "$dashboard_ready" != 1 ]] || ! kill -0 "$apphost_pid" 2>/dev/null; then
'''
if source.count(old_gate) != 1:
    raise SystemExit(f"AppHost start gate marker count={source.count(old_gate)}")
source = source.replace(old_gate, new_gate, 1)
changes.append("fail closed unless direct AppHost and Dashboard HTTPS endpoint remain live")

run_path.write_text(source)
after = hashlib.sha256(source.encode()).hexdigest()

if receipt_path:
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    json.dump({
        "schema": 1,
        "scope": "CI execution harness only; product source, AppHost model, browser exploit, security assertions, and fix/revert controls unchanged",
        "beforeSha256": before,
        "afterSha256": after,
        "changes": changes,
        "authentication": "BrowserToken remains enabled; a random 128-bit token is supplied explicitly per lane",
    }, receipt_path.open("w"), indent=2, sort_keys=True)

print(after)
