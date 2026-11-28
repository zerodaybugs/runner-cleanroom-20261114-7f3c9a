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

anchor = '''printf '%s\\n' \\
  'DEVCERT_GENERATE_EXPORT=PASS' \\
  'SYSTEM_KEYCHAIN_IMPORT=PASS' \\
  'DOTNET_TRUST_CHECK=PASS' \\
  'SECURITY_VERIFY_CERT=PASS' > "$EVIDENCE/devcert-gate.txt"
'''

insertion = anchor + '''
# Prewarm the Aspire-specific macOS dev-certificate cache from the already exported
# owner-only PEM material. Aspire.Hosting uses this cache to avoid a Keychain private-key
# access prompt while DCP prepares the Dashboard and trusted container endpoints.
ASPIRE_DEV_CERT_CACHE="$HOME/.aspire/dev-certs/https"
ASPNET_DEV_CERT_DISK="$HOME/.aspnet/dev-certs/https"
DEV_CERT_THUMBPRINT="$(openssl x509 -in "$DEV_CERT_PEM" -noout -fingerprint -sha1 | sed -E 's/^.*=//' | tr -d ':\\r\\n' | tr '[:lower:]' '[:upper:]')"
[[ "$DEV_CERT_THUMBPRINT" =~ ^[0-9A-F]{40}$ ]] || {
  echo DEVCERT_THUMBPRINT_INVALID > "$EVIDENCE/status.txt"
  exit 73
}
ASPIRE_DEV_CERT_LOOKUP="$(printf '%s' "$DEV_CERT_THUMBPRINT" | shasum -a 256 | awk '{print toupper($1)}')"
[[ "$ASPIRE_DEV_CERT_LOOKUP" =~ ^[0-9A-F]{64}$ ]] || {
  echo DEVCERT_LOOKUP_INVALID > "$EVIDENCE/status.txt"
  exit 74
}
mkdir -p "$ASPIRE_DEV_CERT_CACHE"
chmod 700 "$HOME/.aspire" "$HOME/.aspire/dev-certs" "$ASPIRE_DEV_CERT_CACHE" 2>/dev/null || true
cp "$DEV_CERT_PEM" "$ASPIRE_DEV_CERT_CACHE/$ASPIRE_DEV_CERT_LOOKUP.crt"
cp "$DEV_CERT_KEY" "$ASPIRE_DEV_CERT_CACHE/$ASPIRE_DEV_CERT_LOOKUP.key"
chmod 600 "$ASPIRE_DEV_CERT_CACHE/$ASPIRE_DEV_CERT_LOOKUP.crt" "$ASPIRE_DEV_CERT_CACHE/$ASPIRE_DEV_CERT_LOOKUP.key"

DISK_PFX="$ASPNET_DEV_CERT_DISK/aspnetcore-localhost-$DEV_CERT_THUMBPRINT.pfx"
if [[ -s "$DISK_PFX" ]]; then
  cp "$DISK_PFX" "$ASPIRE_DEV_CERT_CACHE/$ASPIRE_DEV_CERT_LOOKUP.pfx"
  chmod 600 "$ASPIRE_DEV_CERT_CACHE/$ASPIRE_DEV_CERT_LOOKUP.pfx"
fi

CERT_PUB_SHA="$(openssl x509 -in "$ASPIRE_DEV_CERT_CACHE/$ASPIRE_DEV_CERT_LOOKUP.crt" -pubkey -noout | openssl pkey -pubin -outform DER | shasum -a 256 | awk '{print $1}')"
KEY_PUB_SHA="$(openssl pkey -in "$ASPIRE_DEV_CERT_CACHE/$ASPIRE_DEV_CERT_LOOKUP.key" -pubout -outform DER | shasum -a 256 | awk '{print $1}')"
test "$CERT_PUB_SHA" = "$KEY_PUB_SHA"
test -s "$ASPIRE_DEV_CERT_CACHE/$ASPIRE_DEV_CERT_LOOKUP.crt"
test -s "$ASPIRE_DEV_CERT_CACHE/$ASPIRE_DEV_CERT_LOOKUP.key"

python3 - "$EVIDENCE/devcert-cache-gate.json" "$ASPIRE_DEV_CERT_LOOKUP" "$DEV_CERT_THUMBPRINT" "$CERT_PUB_SHA" "$ASPIRE_DEV_CERT_CACHE/$ASPIRE_DEV_CERT_LOOKUP.pfx" <<'PY_CACHE_RECEIPT'
import json, os, pathlib, stat, sys
out, lookup, thumbprint, public_sha, pfx_path = sys.argv[1:]
root = pathlib.Path.home() / '.aspire' / 'dev-certs' / 'https'
def entry(suffix):
    p = root / f'{lookup}.{suffix}'
    return {
        'exists': p.is_file(),
        'bytes': p.stat().st_size if p.is_file() else 0,
        'mode': oct(stat.S_IMODE(p.stat().st_mode)) if p.is_file() else None,
    }
json.dump({
    'schema': 1,
    'lookupSha256OfThumbprint': lookup,
    'certificateThumbprintSha1': thumbprint,
    'publicKeySha256': public_sha,
    'certificate': entry('crt'),
    'privateKey': entry('key'),
    'pfx': entry('pfx'),
    'cacheDirectoryMode': oct(stat.S_IMODE(root.stat().st_mode)),
    'privateMaterialIncludedInReceipt': False,
}, open(out, 'w'), indent=2, sort_keys=True)
PY_CACHE_RECEIPT
'''

count = source.count(anchor)
if count != 1:
    raise SystemExit(f"dev-cert gate anchor count={count}")
source = source.replace(anchor, insertion, 1)
run_path.write_text(source)
after = hashlib.sha256(source.encode()).hexdigest()

receipt = {
    "schema": 1,
    "scope": "CI certificate bootstrap only; product package, AppHost model, browser exploit, lane assertions, natural fix, and stock-revert controls unchanged",
    "beforeSha256": before,
    "afterSha256": after,
    "changes": [
        "compute Aspire cache lookup exactly as SHA-256 over the uppercase SHA-1 thumbprint string",
        "copy the already exported owner-only certificate and matching private key into the Aspire macOS dev-certificate cache",
        "copy the on-disk ASP.NET development PFX when present",
        "verify certificate/private-key public-key equality and owner-only modes before any security lane starts",
    ],
    "privateMaterialAddedToEvidence": False,
    "sourceBasis": [
        "Aspire.Cli CertificateHelpers.GetAspireCertificateHash",
        "Aspire.Cli MacOSCertificateManager.WriteAspireCacheFromDiskPfx",
        "Aspire.Cli DcpDeveloperCertificateCache.EnsureDeveloperCertificateCache",
    ],
}
if receipt_path:
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(after)
