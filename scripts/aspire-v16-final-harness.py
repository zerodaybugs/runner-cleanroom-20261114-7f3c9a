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

def replace_exact(old: str, new: str, label: str, expected: int = 1) -> None:
    global source
    count = source.count(old)
    if count != expected:
        raise SystemExit(f"{label}: expected {expected} matches, got {count}")
    source = source.replace(old, new, expected)
    changes.append(label)

# Immutable base image used by the attacker test service.
replace_exact(
    "FROM python:3.14-slim\n",
    "FROM python:3.14-slim@sha256:22eafb370920ad8b429e0aec3fff433e0669968519f5d60469d83729c138b28b\n",
    "pin attacker Python OCI index digest",
)

# Keep AppHost alive under CI: Aspire treats stdin EOF as a shutdown request.
pattern = re.compile(
    r'(?m)^(?P<i>[ \t]*)dotnet run --no-build --launch-profile https </dev/null > "\$log" 2>&1 &\n'
    r'(?P=i)local apphost_pid=\$!\n'
    r'(?P=i)ACTIVE_APPHOST_PID="\$apphost_pid"\n'
)
matches = list(pattern.finditer(source))
if len(matches) != 1:
    candidates = [line for line in source.splitlines() if 'dotnet run --no-build --launch-profile https' in line]
    raise SystemExit(f'PTY launch marker count={len(matches)}; candidates={candidates!r}')
indent = matches[0].group('i')
python_body = r'''#!/usr/bin/env python3
import errno
import os
import pty
import select
import signal
import sys
import time

log_path, *command = sys.argv[1:]
if not command:
    raise SystemExit('missing command')

child_pid, master_fd = pty.fork()
if child_pid == 0:
    os.environ.setdefault('TERM', 'xterm-256color')
    os.execvp(command[0], command)

shutdown_started = None
sent_term = False
sent_kill = False

def send_group(sig):
    try:
        os.killpg(child_pid, sig)
    except ProcessLookupError:
        pass

def forward(sig, _frame):
    global shutdown_started
    if shutdown_started is None:
        shutdown_started = time.monotonic()
    send_group(signal.SIGINT if sig in (signal.SIGTERM, signal.SIGHUP) else sig)

for watched in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(watched, forward)

status = None
with open(log_path, 'ab', buffering=0) as log:
    while status is None:
        try:
            ready, _, _ = select.select([master_fd], [], [], 0.10)
        except InterruptedError:
            ready = []
        if ready:
            try:
                data = os.read(master_fd, 65536)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                data = b''
            if data:
                log.write(data)
        done, observed = os.waitpid(child_pid, os.WNOHANG)
        if done == child_pid:
            status = observed
            break
        if shutdown_started is not None:
            elapsed = time.monotonic() - shutdown_started
            if elapsed >= 0.70 and not sent_term:
                send_group(signal.SIGTERM)
                sent_term = True
            if elapsed >= 1.35 and not sent_kill:
                send_group(signal.SIGKILL)
                sent_kill = True

try:
    os.close(master_fd)
except OSError:
    pass
raise SystemExit(os.waitstatus_to_exitcode(status))
'''
replacement = (
    f'{indent}local pty_runner="$out/pty-runner.py"\n'
    f'{indent}cat > "$pty_runner" <<\'PY_PTY_RUNNER\'\n'
    + python_body
    + 'PY_PTY_RUNNER\n'
    + f'{indent}chmod 700 "$pty_runner"\n'
    + f'{indent}python3 "$pty_runner" "$log" dotnet run --no-build --launch-profile https &\n'
    + f'{indent}local apphost_pid=$!\n'
    + f'{indent}ACTIVE_APPHOST_PID="$apphost_pid"\n'
)
source, count = pattern.subn(lambda _m: replacement, source, count=1)
if count != 1:
    raise SystemExit('PTY substitution failed')
changes.append('replace stdin-EOF launch with PTY-backed AppHost launcher')

# Parameterize exact SDK/TFM per lane and add current .NET 11 coverage.
replace_exact(
    'write_project() {\n  local dir="$1" version="$2" mode="$3" dash="$4" apphttp="$5" otlp="$6" resource="$7" echoport="$8" proxyport="$9" gwhttp="${10}" gwhttps="${11}" pidlog="${12}"\n',
    'write_project() {\n  local dir="$1" version="$2" mode="$3" dash="$4" apphttp="$5" otlp="$6" resource="$7" echoport="$8" proxyport="$9" gwhttp="${10}" gwhttps="${11}" pidlog="${12}" sdk_version="${13:-10.0.404}" target_framework="${14:-net10.0}"\n',
    'parameterize write_project SDK and target framework',
)
replace_exact(
    '  cat > "$dir/global.json" <<\'EOF\'\n{"sdk":{"version":"10.0.404","rollForward":"disable","allowPrerelease":false}}\nEOF\n',
    '  cat > "$dir/global.json" <<EOF\n{"sdk":{"version":"$sdk_version","rollForward":"disable","allowPrerelease":false}}\nEOF\n',
    'parameterize global.json SDK',
)
replace_exact(
    '    <OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>\n',
    '    <OutputType>Exe</OutputType><TargetFramework>$target_framework</TargetFramework>\n',
    'parameterize Aspire 13 target framework',
)
replace_exact(
    '<PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup>',
    '<PropertyGroup><OutputType>Exe</OutputType><TargetFramework>$target_framework</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup>',
    'parameterize Aspire 17 target framework',
)
replace_exact(
    'run_lane() {\n  local lane="$1" version="$2" mode="$3" base="$4" expected="$5" scope_expect="$6" replacement_dll="${7:-}" export_stock_dll="${8:-}"\n',
    'run_lane() {\n  local lane="$1" version="$2" mode="$3" base="$4" expected="$5" scope_expect="$6" replacement_dll="${7:-}" export_stock_dll="${8:-}" sdk_version="${9:-10.0.404}" target_framework="${10:-net10.0}"\n',
    'parameterize run_lane SDK and target framework',
)
replace_exact(
    '  cleanup_lane "$WORK/"\n  rm -rf "$dir"; write_project "$dir" "$version" "$mode" "$dash" "$apphttp" "$otlp" "$resource" "$echoport" "$proxyport" "$unusedhttp" "$unusedhttps" "$pidlog"\n',
    '  cleanup_lane "$WORK/"\n  rm -rf "$dir"; write_project "$dir" "$version" "$mode" "$dash" "$apphttp" "$otlp" "$resource" "$echoport" "$proxyport" "$unusedhttp" "$unusedhttps" "$pidlog" "$sdk_version" "$target_framework"\n  printf \'SDK_VERSION=%s\\nTARGET_FRAMEWORK=%s\\n\' "$sdk_version" "$target_framework" > "$out/framework-lane.txt"\n',
    'pass SDK/TFM into generated AppHost and record lane provenance',
)
replace_exact(
    '  local appdll="$dir/AppHost/bin/Debug/net10.0/Aspire.Hosting.dll"\n',
    '  local appdll="$dir/AppHost/bin/Debug/$target_framework/Aspire.Hosting.dll"\n',
    'resolve Aspire.Hosting assembly from lane target framework',
)
replace_exact(
    'run_lane current_17_0_0_legacy 17.0.0 legacy 18600 positive frontend-exposed "" "$STOCKDLL" || matrix_rc=1\n\nFIXDIR=',
    'run_lane current_17_0_0_legacy 17.0.0 legacy 18600 positive frontend-exposed "" "$STOCKDLL" 10.0.404 net10.0 || matrix_rc=1\nrun_lane current_17_0_0_net11_legacy 17.0.0 legacy 19000 positive frontend-exposed "" "" 11.0.100 net11.0 || matrix_rc=1\n\nFIXDIR=',
    'add Aspire 17.0.0 current .NET 11 positive lane',
)

# Require AppHost and victim health after the browser test so fixed-negative cannot pass on infrastructure failure.
replace_exact(
    '  local browser_rc=$?\n  [[ -f "$pidlog" ]] && { stat -f \'MODE=%Lp UID=%u GID=%g BYTES=%z\' "$pidlog" > "$out/victim-pid-log-stat.txt"; cat "$pidlog" > "$out/victim-pids.txt"; }\n',
    '''  local browser_rc=$?
  local apphost_alive_post_browser=0 latest_victim_pid='' victim_alive_post_browser=0
  kill -0 "$apphost_pid" 2>/dev/null && apphost_alive_post_browser=1
  if [[ -f "$pidlog" ]]; then
    stat -f 'MODE=%Lp UID=%u GID=%g BYTES=%z' "$pidlog" > "$out/victim-pid-log-stat.txt"
    cat "$pidlog" > "$out/victim-pids.txt"
    latest_victim_pid="$(tail -n 1 "$pidlog" | tr -d '[:space:]')"
    [[ "$latest_victim_pid" =~ ^[0-9]+$ ]] && kill -0 "$latest_victim_pid" 2>/dev/null && victim_alive_post_browser=1
  fi
  python3 - "$out/post-browser-health.json" "$apphost_alive_post_browser" "$latest_victim_pid" "$victim_alive_post_browser" <<'PY_HEALTH'
import json,sys
out,apphost,pid,victim=sys.argv[1:]
json.dump({
    'appHostAlive': apphost == '1',
    'latestVictimPid': int(pid) if pid.isdigit() else None,
    'latestVictimPidAlive': victim == '1',
}, open(out,'w'), indent=2, sort_keys=True)
PY_HEALTH
''',
    'record post-browser AppHost and victim health',
)
replace_exact(
    '  python3 - "$out/browser-result.json" "$expected" "$scope_rc" "$browser_rc" "$out/assertion.txt" <<\'PY_ASSERT\'\nimport json,sys\np,expected,scope_rc,browser_rc,out=sys.argv[1:]\nj=json.load(open(p))\npositive=bool(j.get(\'linkedServiceOpened\') and j.get(\'cookieLeak\') and j.get(\'replayAuthenticated\') and j.get(\'stockLifecycleExecuted\') and j.get(\'stopExecuted\') and j.get(\'startExecuted\'))\nfixed_negative=bool(j.get(\'linkedServiceOpened\') and j.get(\'cookieLeak\') and not j.get(\'replayAuthenticated\') and not j.get(\'stockLifecycleExecuted\'))\n',
    '  python3 - "$out/browser-result.json" "$out/post-browser-health.json" "$expected" "$scope_rc" "$browser_rc" "$out/assertion.txt" <<\'PY_ASSERT\'\nimport json,sys\np,health_path,expected,scope_rc,browser_rc,out=sys.argv[1:]\nj=json.load(open(p))\nhealth=json.load(open(health_path))\npost_health=bool(health.get(\'appHostAlive\') and health.get(\'latestVictimPidAlive\'))\npositive=bool(post_health and j.get(\'dashboardConnected\') and j.get(\'linkedServiceOpened\') and j.get(\'cookieLeak\') and j.get(\'replayAuthenticated\') and j.get(\'stockLifecycleExecuted\') and j.get(\'stopExecuted\') and j.get(\'startExecuted\'))\nfixed_negative=bool(post_health and j.get(\'dashboardConnected\') and j.get(\'linkedServiceOpened\') and j.get(\'cookieLeak\') and not j.get(\'replayAuthenticated\') and not j.get(\'stockLifecycleExecuted\'))\n',
    'bind security assertions to healthy post-browser infrastructure',
)
replace_exact(
    "    f.write(f'EXPECTED={expected}\\nPOSITIVE_CHAIN={int(positive)}\\nFIXED_NEGATIVE={int(fixed_negative)}\\nDCP_SCOPE_RC={scope_rc}\\nBROWSER_RC={browser_rc}\\nASSERTION={\"PASS\" if ok else \"FAIL\"}\\n')\n",
    "    f.write(f'EXPECTED={expected}\\nPOST_BROWSER_HEALTH={int(post_health)}\\nPOSITIVE_CHAIN={int(positive)}\\nFIXED_NEGATIVE={int(fixed_negative)}\\nDCP_SCOPE_RC={scope_rc}\\nBROWSER_RC={browser_rc}\\nASSERTION={\"PASS\" if ok else \"FAIL\"}\\n')\n",
    'record post-browser health in assertion receipt',
)

run_path.write_text(source)
after = hashlib.sha256(source.encode()).hexdigest()
if receipt_path:
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    json.dump({
        'schema': 3,
        'scope': 'execution harness hardening only; product source and browser exploit logic unchanged',
        'beforeSha256': before,
        'afterSha256': after,
        'changes': changes,
    }, receipt_path.open('w'), indent=2, sort_keys=True)
print(after)
