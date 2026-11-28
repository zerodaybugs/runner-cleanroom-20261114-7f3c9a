#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

EXPECTED_INPUT_SHA256 = "55c6470e32a2ed5602ff0a450a587966ad6f40b9a5b88eb7a4d3514edf235906"
VALID_LANES = {
    "first_patched",
    "current_net10_revert",
    "current_net11",
    "natural_fix",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def die(message: str) -> None:
    raise SystemExit(message)


def main() -> None:
    if len(sys.argv) != 4:
        die(f"usage: {sys.argv[0]} <run.sh> <lane> <receipt.json>")

    run_path = Path(sys.argv[1])
    lane = sys.argv[2]
    receipt_path = Path(sys.argv[3])
    if lane not in VALID_LANES:
        die(f"unsupported lane: {lane}")
    if not run_path.is_file():
        die(f"missing run script: {run_path}")

    original = run_path.read_bytes()
    before_sha = sha256_bytes(original)
    if before_sha != EXPECTED_INPUT_SHA256:
        die(f"unexpected v20 input hash: {before_sha}")
    source = original.decode("utf-8")

    old_devcert = (
        'dotnet dev-certs https -ep "$DEV_CERT_PEM" --trust --format PEM '
        '> "$EVIDENCE/devcert-create-trust.log" 2>&1'
    )
    if source.count(old_devcert) != 1:
        die(f"devcert anchor count={source.count(old_devcert)}")

    new_devcert = r'''DEV_CERT_PFX="$CERT_DIR/aspire-devcert.pfx"
DEV_CERT_KEY="$CERT_DIR/aspire-devcert.key"
DEV_CERT_PFX_PASS="$(openssl rand -hex 24)"
DEV_CERT_SYSTEM_KEYCHAIN=/Library/Keychains/System.keychain
python3 - "$DEV_CERT_PFX" "$DEV_CERT_PFX_PASS" "$EVIDENCE/devcert-create-export.log" <<'PY_DEVCERT_EXPORT'
import subprocess,sys
pfx,password,log_path=sys.argv[1:]
with open(log_path,'w',encoding='utf-8') as log:
    subprocess.run(
        ['dotnet','dev-certs','https','-ep',pfx,'-p',password],
        stdout=log,
        stderr=subprocess.STDOUT,
        check=True,
        timeout=60,
    )
PY_DEVCERT_EXPORT
openssl pkcs12 -in "$DEV_CERT_PFX" -passin "pass:$DEV_CERT_PFX_PASS" -clcerts -nokeys -out "$DEV_CERT_PEM"
openssl pkcs12 -in "$DEV_CERT_PFX" -passin "pass:$DEV_CERT_PFX_PASS" -nocerts -nodes -out "$DEV_CERT_KEY"
test -s "$DEV_CERT_PEM"
test -s "$DEV_CERT_KEY"
DEV_CERT_SHA1="$(openssl x509 -in "$DEV_CERT_PEM" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
test "${#DEV_CERT_SHA1}" = 40
python3 - "$DEV_CERT_PEM" "$DEV_CERT_SYSTEM_KEYCHAIN" "$EVIDENCE/devcert-system-keychain.log" <<'PY_DEVCERT_SYSTEM_KEYCHAIN'
import subprocess,sys
cert,keychain,log_path=sys.argv[1:]
commands=[
    ['sudo','-n','security','add-trusted-cert','-d','-r','trustRoot','-k',keychain,cert],
    ['security','verify-cert','-c',cert,'-p','ssl'],
]
with open(log_path,'w',encoding='utf-8') as log:
    for index,command in enumerate(commands,1):
        log.write(f'COMMAND_{index}={" ".join(command[:4])}\n')
        log.flush()
        subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=45)
PY_DEVCERT_SYSTEM_KEYCHAIN
openssl x509 -in "$DEV_CERT_PEM" -noout -subject -issuer -serial -fingerprint -sha256 > "$EVIDENCE/devcert-metadata.txt"
printf 'SYSTEM_KEYCHAIN=%s\nCERT_SHA1=%s\n' "$DEV_CERT_SYSTEM_KEYCHAIN" "$DEV_CERT_SHA1" >> "$EVIDENCE/devcert-metadata.txt"'''
    source = source.replace(old_devcert, new_devcert, 1)

    start_marker = "matrix_rc=0\n# Independent residual replication: only the mandatory first-patched/current/fix/revert lanes."
    end_marker = "\npython3 - \"$EVIDENCE\" <<'PY_SUMMARY'"
    start = source.find(start_marker)
    if start < 0:
        die("matrix start marker missing")
    end = source.find(end_marker, start)
    if end < 0:
        die("matrix end marker missing")

    lane_blocks = {
        "first_patched": r'''matrix_rc=0
# V21 parallel lane: exact first patched release.
run_lane first_patched_13_6_5_legacy 13.6.5 legacy 18400 positive frontend-exposed || matrix_rc=1
''',
        "current_net10_revert": r'''matrix_rc=0
# V21 parallel lane: current .NET 10 positive plus exact stock-assembly revert.
STOCKDLL="$WORK/Aspire.Hosting.stock-17.0.0.dll"
run_lane current_17_0_0_legacy 17.0.0 legacy 18600 positive frontend-exposed "" "$STOCKDLL" 10.0.404 net10.0 || matrix_rc=1
if [[ -f "$STOCKDLL" ]]; then
  run_lane current_17_0_0_legacy_revert_stock 17.0.0 legacy-revert 18800 positive frontend-exposed "$STOCKDLL" || matrix_rc=1
else
  mkdir -p "$EVIDENCE/current_17_0_0_legacy_revert_stock"
  echo STOCK_DLL_MISSING > "$EVIDENCE/current_17_0_0_legacy_revert_stock/status.txt"
  matrix_rc=1
fi
''',
        "current_net11": r'''matrix_rc=0
# V21 parallel lane: current .NET 11 positive release gate.
run_lane current_17_0_0_net11_legacy 17.0.0 legacy 19000 positive frontend-exposed "" "" 11.0.100 net11.0 || matrix_rc=1
''',
        "natural_fix": r'''matrix_rc=0
# V21 parallel lane: source-built natural fix, expected fail-closed.
FIXDIR="$EVIDENCE/natural_fix_control"
mkdir -p "$FIXDIR"
FIXDLL="$WORK/Aspire.Hosting.natural-fix.dll"
if build_natural_fix "$FIXDLL" "$FIXDIR"; then
  sha256sum "$FIXDLL" > "$FIXDIR/fix-dll.sha256"
  run_lane current_17_0_0_legacy_natural_fix 17.0.0 legacy-fix 18700 fixed-negative frontend-removed-otlp-kept "$FIXDLL" || matrix_rc=1
else
  echo FIX_BUILD_FAILED > "$FIXDIR/status.txt"
  matrix_rc=1
fi
''',
    }
    source = source[:start] + lane_blocks[lane] + source[end:]

    if "--trust --format PEM" in source:
        die("interactive dev-certs trust flag remains")
    if source.count("V21 parallel lane:") != 1:
        die("lane replacement count mismatch")
    if "--ignore-certificate-errors" in source:
        die("forbidden Chromium trust bypass present")
    if "sudo -n security add-trusted-cert" not in source:
        die("validated system-keychain trust command missing")

    output = source.encode("utf-8")
    run_path.write_bytes(output)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema": 2,
        "lane": lane,
        "scope": "CI partitioning and noninteractive macOS System.keychain trust only; product source, browser exploit logic, security assertions, and fix semantics unchanged",
        "inputRunSha256": before_sha,
        "outputRunSha256": sha256_bytes(output),
        "certificateTrust": {
            "store": "/Library/Keychains/System.keychain",
            "addCommand": "sudo -n security add-trusted-cert",
            "browserBypass": False,
            "validatedByRunId": 46173931175,
        },
        "changes": [
            "replace interactive dotnet dev-certs --trust with bounded PFX export",
            "mark the exported public development certificate trusted in the macOS System.keychain using passwordless sudo",
            "select exactly one independent residual lane group per macOS job",
            "preserve stock Dashboard navigation, cookie replay, lifecycle sink, natural-fix assertion, and stock-revert assertion",
        ],
    }
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(receipt["outputRunSha256"])


if __name__ == "__main__":
    main()
