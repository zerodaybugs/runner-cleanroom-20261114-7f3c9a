#!/usr/bin/env python3
import hashlib, json, pathlib, sys

EXPECTED_INPUT_SHA256 = '1f3057ecc1dfe1e30affa959c06788447ac9844701f936288292b7e3ac359150'

if len(sys.argv) not in (2, 3):
    raise SystemExit(f"usage: {sys.argv[0]} RUN_SH [RECEIPT_JSON]")
run_path = pathlib.Path(sys.argv[1])
receipt_path = pathlib.Path(sys.argv[2]) if len(sys.argv) == 3 else None
source = run_path.read_text()
before = hashlib.sha256(source.encode()).hexdigest()
if before != EXPECTED_INPUT_SHA256:
    raise SystemExit(f'unexpected input SHA-256: {before}')
changes=[]

cleanup_old = '''    ACTIVE_APPHOST_PID=""
  fi
  if [[ -n "$marker" ]]; then
'''
cleanup_new = '''    ACTIVE_APPHOST_PID=""
  fi
  exec 9>&- 2>/dev/null || true
  if [[ -n "$marker" ]]; then
'''
if source.count(cleanup_old) != 1:
    raise SystemExit(f'cleanup marker count={source.count(cleanup_old)}')
source = source.replace(cleanup_old, cleanup_new, 1)
changes.append('close the FIFO keepalive descriptor during lane cleanup')

start_marker = '  local browser_token apphost_dll\n'
end_marker = '  printf \'%s\\n\' "$apphost_pid" > "$out/apphost.pid"\n'
if source.count(start_marker) != 1 or source.count(end_marker) != 1:
    raise SystemExit(f'launch markers start={source.count(start_marker)} end={source.count(end_marker)}')
start = source.index(start_marker)
end = source.index(end_marker, start)
replacement = '''  local browser_token apphost_dll stdin_fifo
  browser_token="$(openssl rand -hex 16)"
  apphost_dll="$dir/AppHost/bin/Debug/$target_framework/AppHost.dll"
  test -f "$apphost_dll" || { echo APPHOST_DLL_MISSING > "$out/status.txt"; return 1; }
  printf '%s\\n' "$(sha256sum "$apphost_dll" | awk '{print $1}')" > "$out/apphost-dll.sha256"
  stdin_fifo="$out/apphost.stdin"
  rm -f "$stdin_fifo"
  mkfifo -m 600 "$stdin_fifo"
  exec 9<>"$stdin_fifo"
  ASPNETCORE_ENVIRONMENT=Development \\
  DOTNET_ENVIRONMENT=Development \\
  ASPIRE_DASHBOARD_FRONTEND_BROWSERTOKEN="$browser_token" \\
  dotnet run --no-build --launch-profile https <&9 > "$log" 2>&1 &
  local apphost_pid=$!
  ACTIVE_APPHOST_PID="$apphost_pid"
  rm -f "$stdin_fifo"
'''
source = source[:start] + replacement + source[end:]
changes.append('restore the official dotnet-run launch path with non-EOF FIFO stdin and an explicit random BrowserToken')

run_path.write_text(source)
after=hashlib.sha256(source.encode()).hexdigest()
receipt={
  'schema':1,
  'scope':'CI AppHost launch transport only; product packages, AppHost model, trusted-YARP backend, browser exploit, assertions, natural fix and stock revert controls unchanged',
  'beforeSha256':before,
  'afterSha256':after,
  'changes':changes,
  'launch':'dotnet run --no-build --launch-profile https',
  'stdin':'0600 FIFO held open through fd 9; no PTY and no stdin EOF',
  'authentication':'random explicit 128-bit BrowserToken per lane',
}
if receipt_path:
    receipt_path.parent.mkdir(parents=True,exist_ok=True)
    receipt_path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(after)
