#!/usr/bin/env python3
import argparse, hashlib, json, pathlib, re, shutil

TEXT_NAMES = {
    'assertion.txt','readiness.txt','status.txt','workflow-status.txt','bootstrap-status.txt',
    'dcp-scope-assertion.json','browser-result.json','post-browser-health.json','framework-lane.txt',
    'browser.stderr','browser.stdout','apphost.log','apphost-tail.txt','docker-ps-a.txt','docker-ps-final.txt',
    'patch-v11-status.txt','patch-v13-status.txt','natural-fix.patch','fix-build.log','fix-dll.sha256',
    'aspire-hosting-loaded.sha256','aspire-hosting-before-replacement.sha256','exported-stock-dll.sha256',
    'patched-hashes.txt','PATCH_CHAIN.json','V13_PATCH_MANIFEST.json','HARNESS_FINAL_PATCH.json',
    'executed-run-hashes.txt','matrix-summary.json','victim-pids.txt','victim-pid-log-stat.txt',
    'fix-build-status.txt','revert-status.txt','metadata.txt','dcp-services.json','dcp-tunnels.json',
    'capture-meta.json','attacker-container-inspect.json','build.log','dotnet-lane.txt','runner-provenance.txt',
    'dotnet-info.txt','dotnet-list-sdks.txt','dotnet-list-runtimes.txt','docker-version.txt','uname.txt','sw_vers.txt'
}
IMAGE_RE = re.compile(r'(?i).*(dashboard|attacker|replay|resource|linked|lifecycle).*\.(png|jpg|jpeg)$')
TOKEN_PATTERNS = [
    (re.compile(r'([?&](?:t|token|access_token|code)=)[^&\s"\']+', re.I), r'\1<REDACTED>'),
    (re.compile(r'(?im)^((?:authorization|proxy-authorization)\s*:\s*).+$'), r'\1<REDACTED>'),
    (re.compile(r'(?im)^((?:cookie|set-cookie)\s*:\s*).+$'), r'\1<REDACTED>'),
    (re.compile(r'(?i)(\.AspNetCore\.[A-Za-z0-9_.-]+=)[^;\s"\']+'), r'\1<REDACTED>'),
    (re.compile(r'(?i)("(?:cookie|token|authorization|accessToken|dashboardToken)"\s*:\s*")[^"]+'), r'\1<REDACTED>'),
]

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()

def sanitize(text):
    for pattern,repl in TOKEN_PATTERNS: text=pattern.sub(repl,text)
    return text

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('root',type=pathlib.Path)
    ap.add_argument('output',type=pathlib.Path)
    ns=ap.parse_args(); root=ns.root; out=ns.output
    if not root.is_dir(): raise SystemExit(f'root missing: {root}')
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True)
    inventory=[]
    for src in sorted(root.rglob('*')):
        if not src.is_file(): continue
        rel=src.relative_to(root)
        is_text=src.name in TEXT_NAMES
        is_image=bool(IMAGE_RE.fullmatch(src.name))
        if not (is_text or is_image): continue
        dst=out/rel; dst.parent.mkdir(parents=True,exist_ok=True)
        if is_text:
            dst.write_text(sanitize(src.read_text(errors='replace')))
            kind='sanitized-text'
        else:
            shutil.copyfile(src,dst); kind='binary-image'
        inventory.append({'path':str(rel),'kind':kind,'bytes':dst.stat().st_size,'sha256':sha(dst)})
    (out/'INVENTORY.json').write_text(json.dumps(inventory,indent=2,sort_keys=True)+'\n')
    lines=[]
    for p in sorted(out.rglob('*')):
        if p.is_file() and p.name!='SHA256SUMS.txt': lines.append(f'{sha(p)}  {p.relative_to(out)}')
    (out/'SHA256SUMS.txt').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'files':len(inventory),'output':str(out)},sort_keys=True))
if __name__=='__main__': main()
