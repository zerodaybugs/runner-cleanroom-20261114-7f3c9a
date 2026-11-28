#!/usr/bin/env python3
import hashlib
import json
import pathlib
import sys

if len(sys.argv) not in (2, 3):
    raise SystemExit(f"usage: {sys.argv[0]} RUN_SH [RECEIPT_JSON]")

run_path = pathlib.Path(sys.argv[1])
receipt_path = pathlib.Path(sys.argv[2]) if len(sys.argv) == 3 else None
source = run_path.read_text()
before = hashlib.sha256(source.encode()).hexdigest()

old_wait = '  local max_wait=90 linked_ready=0 attacker_ready=0\n'
new_wait = '  local max_wait=300 linked_ready=0 attacker_ready=0\n'
if source.count(old_wait) != 1:
    raise SystemExit(f"linked readiness wait count={source.count(old_wait)}")
source = source.replace(old_wait, new_wait, 1)

old_failure = '''    for c in $(docker ps -a --filter ancestor=attacker-yarp-backend:local --format '{{.Names}}'); do docker logs "$c" > "$out/attacker-$c.log" 2>&1 || true; docker inspect "$c" > "$out/attacker-$c.inspect.json" 2>/dev/null || true; done
    cleanup_lane "$WORK/"
    return 1
'''
new_failure = '''    while IFS= read -r c; do
      [[ -n "$c" ]] || continue
      safe_name="$(printf '%s' "$c" | tr -c 'A-Za-z0-9._-' '_')"
      docker logs "$c" > "$out/container-$safe_name.log" 2>&1 || true
      docker inspect --format '{{json .State}}' "$c" > "$out/container-$safe_name.state.json" 2>/dev/null || true
      docker inspect --format '{{json .NetworkSettings.Ports}}' "$c" > "$out/container-$safe_name.ports.json" 2>/dev/null || true
    done < <(docker ps -a --format '{{.Names}}')
    lsof -nP -iTCP -sTCP:LISTEN > "$out/host-listeners.txt" 2>&1 || true
    cleanup_lane "$WORK/"
    return 1
'''
if source.count(old_failure) != 1:
    raise SystemExit(f"linked readiness failure block count={source.count(old_failure)}")
source = source.replace(old_failure, new_failure, 1)

run_path.write_text(source)
after = hashlib.sha256(source.encode()).hexdigest()

receipt = {
    "schema": 1,
    "scope": "CI timing and failure diagnostics only; product packages, AppHost model, browser exploit, security assertions, natural fix and stock-revert controls unchanged",
    "beforeSha256": before,
    "afterSha256": after,
    "changes": [
        "increase the linked YARP readiness bound from 90 to 300 seconds for software-emulated QEMU containers",
        "on readiness failure, preserve redaction-compatible per-container state, port, log, and host-listener diagnostics",
    ],
    "securityPredicateChanged": False,
    "successAssertionChanged": False,
}
if receipt_path:
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(after)
