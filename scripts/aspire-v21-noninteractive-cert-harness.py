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

old = '''CERT_DIR="$WORK/trusted-devcert"
DEV_CERT_PEM="$CERT_DIR/aspire-devcert.crt"
rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR"
dotnet dev-certs https --clean > "$EVIDENCE/devcert-clean.log" 2>&1 || true
dotnet dev-certs https -ep "$DEV_CERT_PEM" --trust --format PEM > "$EVIDENCE/devcert-create-trust.log" 2>&1
dotnet dev-certs https --check --trust > "$EVIDENCE/devcert-check-trust.log" 2>&1
openssl x509 -in "$DEV_CERT_PEM" -noout -subject -issuer -serial -dates -fingerprint -sha256 > "$EVIDENCE/devcert-public-metadata.txt"
sha256sum "$DEV_CERT_PEM" > "$EVIDENCE/devcert-public.sha256"
security find-certificate -c localhost -p > "$EVIDENCE/keychain-localhost-cert.pem" 2>/dev/null || true
if [[ -s "$EVIDENCE/keychain-localhost-cert.pem" ]]; then
  openssl x509 -in "$EVIDENCE/keychain-localhost-cert.pem" -noout -fingerprint -sha256 > "$EVIDENCE/keychain-localhost-cert.sha256.txt"
fi
'''

new = '''run_timeout() {
  local seconds="$1"
  shift
  python3 - "$seconds" "$@" <<'PY_TIMEOUT'
import subprocess
import sys
seconds = float(sys.argv[1])
command = sys.argv[2:]
try:
    completed = subprocess.run(command, timeout=seconds, check=False)
    raise SystemExit(completed.returncode)
except subprocess.TimeoutExpired:
    print(f'TIMEOUT after {seconds}s: {command}', file=sys.stderr)
    raise SystemExit(124)
PY_TIMEOUT
}

CERT_DIR="$WORK/trusted-devcert"
DEV_CERT_PEM="$CERT_DIR/aspire-devcert.crt"
DEV_CERT_KEY="$CERT_DIR/aspire-devcert.key"
rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR"
run_timeout 60 dotnet dev-certs https --clean > "$EVIDENCE/devcert-clean.log" 2>&1 || true
run_timeout 60 dotnet dev-certs https \\
  --export-path "$DEV_CERT_PEM" \\
  --format PEM \\
  --no-password > "$EVIDENCE/devcert-create-export.log" 2>&1
[[ -s "$DEV_CERT_PEM" && -s "$DEV_CERT_KEY" ]] || {
  echo DEVCERT_EXPORT_MISSING > "$EVIDENCE/status.txt"
  exit 72
}
run_timeout 60 sudo security add-trusted-cert \\
  -d \\
  -r trustRoot \\
  -k /Library/Keychains/System.keychain \\
  "$DEV_CERT_PEM" > "$EVIDENCE/devcert-system-trust.log" 2>&1
run_timeout 60 dotnet dev-certs https --check --trust > "$EVIDENCE/devcert-check-trust.log" 2>&1
run_timeout 60 security verify-cert \\
  -c "$DEV_CERT_PEM" \\
  -p ssl \\
  -s localhost > "$EVIDENCE/devcert-security-verify.log" 2>&1
openssl x509 -in "$DEV_CERT_PEM" -noout -subject -issuer -serial -dates -fingerprint -sha256 > "$EVIDENCE/devcert-public-metadata.txt"
sha256sum "$DEV_CERT_PEM" > "$EVIDENCE/devcert-public.sha256"
security find-certificate -c localhost -p > "$EVIDENCE/keychain-localhost-cert.pem" 2>/dev/null || true
if [[ -s "$EVIDENCE/keychain-localhost-cert.pem" ]]; then
  openssl x509 -in "$EVIDENCE/keychain-localhost-cert.pem" -noout -fingerprint -sha256 > "$EVIDENCE/keychain-localhost-cert.sha256.txt"
fi
printf '%s\\n' \\
  'DEVCERT_GENERATE_EXPORT=PASS' \\
  'SYSTEM_KEYCHAIN_IMPORT=PASS' \\
  'DOTNET_TRUST_CHECK=PASS' \\
  'SECURITY_VERIFY_CERT=PASS' > "$EVIDENCE/devcert-gate.txt"
'''

count = source.count(old)
if count != 1:
    raise SystemExit(f"development certificate block count={count}")
source = source.replace(old, new, 1)

run_path.write_text(source)
after = hashlib.sha256(source.encode()).hexdigest()

receipt = {
    "schema": 1,
    "scope": "CI certificate bootstrap only; product packages, AppHost model, browser exploit, lane assertions, natural fix, and stock revert controls unchanged",
    "beforeSha256": before,
    "afterSha256": after,
    "changes": [
        "replace interactive dotnet dev-certs --trust with noninteractive PEM export",
        "import only the public development certificate into the macOS System keychain using security add-trusted-cert",
        "add bounded 60-second subprocess watchdogs for every certificate bootstrap operation",
        "verify both dotnet trust state and macOS SSL trust before any security lane starts",
    ],
    "validatedBy": "macos-15-arm64 smoke run 46044334223",
}
if receipt_path:
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(after)
