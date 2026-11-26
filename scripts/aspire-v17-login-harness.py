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
changes = []

def replace_exact(old: str, new: str, label: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected 1 match, got {count}")
    source = source.replace(old, new, 1)
    changes.append(label)

replace_exact(
    "import errno\nimport os\nimport pty\nimport select\n",
    "import errno\nimport fcntl\nimport os\nimport pty\nimport struct\nimport termios\nimport select\n",
    "add PTY geometry imports",
)
replace_exact(
    "child_pid, master_fd = pty.fork()\nif child_pid == 0:\n    os.environ.setdefault('TERM', 'xterm-256color')\n    os.execvp(command[0], command)\n\nshutdown_started = None\n",
    "child_pid, master_fd = pty.fork()\nwindow = struct.pack('HHHH', 120, 4096, 0, 0)\nif child_pid == 0:\n    fcntl.ioctl(0, termios.TIOCSWINSZ, window)\n    os.environ.setdefault('TERM', 'xterm-256color')\n    os.environ['COLUMNS'] = '4096'\n    os.environ['LINES'] = '120'\n    os.execvp(command[0], command)\nfcntl.ioctl(master_fd, termios.TIOCSWINSZ, window)\n\nshutdown_started = None\n",
    "set 4096-column PTY to prevent Aspire login URL wrapping",
)
replace_exact(
    '''  local login=''
  for i in $(seq 1 180); do
    login=$(grep -Eo 'https://localhost:[0-9]+/login\\?t=[-A-Za-z0-9_]+' "$log" | tail -1 || true)
    [[ -n "$login" ]] && break
    grep -q 'Unhandled exception' "$log" && break
    sleep 1
  done
''',
    '''  local login=''
  for i in $(seq 1 180); do
    login=$(python3 - "$log" "$dash" <<'PY_LOGIN_URL'
import re, string, sys
path, port = sys.argv[1:]
raw = open(path, 'rb').read().decode('utf-8', 'ignore')
raw = re.sub(r'\\x1b\\][^\\x07]*(?:\\x07|\\x1b\\\\)', '', raw)
raw = re.sub(r'\\x1b\\[[0-?]*[ -/]*[@-~]', '', raw)
raw = re.sub(r'\\x1b[=>]', '', raw)
marker = f'https://localhost:{port}/login?t='
pos = raw.rfind(marker)
if pos >= 0:
    token = []
    for ch in raw[pos + len(marker):]:
        if ch in string.hexdigits:
            token.append(ch.lower())
            if len(token) == 32:
                break
        elif ch.isspace():
            continue
        else:
            break
    if len(token) == 32:
        print(marker + ''.join(token))
PY_LOGIN_URL
)
    [[ -n "$login" ]] && break
    grep -q 'Unhandled exception' "$log" && break
    sleep 1
  done
  python3 - "$out/login-token-shape.json" "$login" <<'PY_LOGIN_RECEIPT'
import hashlib, json, sys, urllib.parse
out, url = sys.argv[1:]
parsed = urllib.parse.urlsplit(url) if url else None
token = urllib.parse.parse_qs(parsed.query).get('t', [''])[0] if parsed else ''
json.dump({
    'loginUrlPresent': bool(url),
    'scheme': parsed.scheme if parsed else None,
    'host': parsed.hostname if parsed else None,
    'port': parsed.port if parsed else None,
    'path': parsed.path if parsed else None,
    'tokenLength': len(token),
    'tokenIsLowerHex32': len(token) == 32 and all(c in '0123456789abcdef' for c in token),
    'loginUrlSha256': hashlib.sha256(url.encode()).hexdigest() if url else None,
}, open(out, 'w'), indent=2, sort_keys=True)
PY_LOGIN_RECEIPT
''',
    "replace line-fragile grep with ANSI/wrap-safe exact 32-hex login-token parser",
)

run_path.write_text(source)
after = hashlib.sha256(source.encode()).hexdigest()
if receipt_path:
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    json.dump({
        "schema": 1,
        "scope": "CI PTY geometry and Dashboard login URL parsing only; product source and browser exploit logic unchanged",
        "beforeSha256": before,
        "afterSha256": after,
        "changes": changes,
        "officialTokenShape": "32 lowercase hexadecimal characters (128-bit entropy)",
    }, receipt_path.open("w"), indent=2, sort_keys=True)
print(after)
