param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('net10','net11')]
    [string]$Lane,
    [Parameter(Mandatory = $true)]
    [string]$Runner,
    [Parameter(Mandatory = $true)]
    [string]$RunId,
    [Parameter(Mandatory = $true)]
    [string]$SourceSha
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repo = (Get-Location).Path
$inputDir = Join-Path $repo 'sealed/pathstring-staticfiles-final-v2'
$payloadZip = Join-Path $repo 'pathstring-final-v2.payload.zip'
$payloadDir = Join-Path $repo 'pathstring-final-v2-payload'
$runtimeKeyPath = Join-Path $repo 'pathstring-final-v2.runtime.key'
$evidence = Join-Path $repo ("evidence-pathstring-final-v2-{0}-{1}" -f $Lane,$Runner)
$sealedOut = Join-Path $repo 'sealed-final-evidence'
$plainEvidenceZip = Join-Path $repo 'evidence-final-v2.plain.zip'
$executeOutcome = 'failure'
$failureText = $null
$payloadKey = $null
$privatePemBytes = $null
$wrappingKey = $null
$matrix = @{
    net10 = @{ Sdk='10.0.404'; Runtime='10.0.15' }
    net11 = @{ Sdk='11.0.100'; Runtime='11.0.0' }
}
$entry = $matrix[$Lane]
Remove-Item -LiteralPath $payloadZip,$payloadDir,$runtimeKeyPath,$evidence,$sealedOut,$plainEvidenceZip -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $evidence | Out-Null
try {
    if ([string]::IsNullOrWhiteSpace($env:WRAPPING_KEY_B64)) { throw 'wrapping key missing' }
    $wrappingKey = [Convert]::FromBase64String($env:WRAPPING_KEY_B64)
    if ($wrappingKey.Length -ne 32) { throw 'wrapping key length invalid' }
    $wrappedPrivate = [IO.File]::ReadAllBytes((Join-Path $repo 'bootstrap/private.pem.enc'))
    $wrapIv = [Convert]::FromHexString((Get-Content -LiteralPath (Join-Path $repo 'bootstrap/private.iv.hex') -Raw).Trim())
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $wrappingKey
        $aes.IV = $wrapIv
        $dec = $aes.CreateDecryptor()
        try { $privatePemBytes = $dec.TransformFinalBlock($wrappedPrivate, 0, $wrappedPrivate.Length) }
        finally { $dec.Dispose() }
    }
    finally { $aes.Dispose() }
    $wrappedPayloadKey = [Convert]::FromBase64String((Get-Content -LiteralPath (Join-Path $inputDir 'payload.key.enc.b64') -Raw).Trim())
    $wrappedHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($wrappedPayloadKey)).ToLowerInvariant()
    if ($wrappedHash -ne '5c3ca96e97a2ea818f9677cfc8c398a45042c66b1cff61a384fcf61ee546dea2') { throw "wrapped key hash mismatch: $wrappedHash" }
    $rsa = [Security.Cryptography.RSA]::Create()
    try {
        $rsa.ImportFromPem([Text.Encoding]::ASCII.GetString($privatePemBytes))
        $payloadKey = $rsa.Decrypt($wrappedPayloadKey, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    }
    finally { $rsa.Dispose() }
    if ($payloadKey.Length -ne 32) { throw 'payload key length invalid' }
    [IO.File]::WriteAllBytes($runtimeKeyPath, $payloadKey)
    $cipherB64 = ((Get-ChildItem -LiteralPath $inputDir -File -Filter 'payload.enc.part-*' | Sort-Object Name | ForEach-Object { (Get-Content -LiteralPath $_.FullName -Raw).Trim() }) -join '')
    $cipher = [Convert]::FromBase64String($cipherB64)
    $cipherHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($cipher)).ToLowerInvariant()
    if ($cipherHash -ne '31bfcb9af19ac6483c90d291988d7743cde303171b05b3c89b0e8348da088820') { throw "cipher hash mismatch: $cipherHash" }
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $payloadKey
        $aes.IV = [Convert]::FromHexString('03c845d2cdcc6181685289da3740728c')
        $dec = $aes.CreateDecryptor()
        try { $plain = $dec.TransformFinalBlock($cipher, 0, $cipher.Length) }
        finally { $dec.Dispose() }
    }
    finally { $aes.Dispose() }
    $plainHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($plain)).ToLowerInvariant()
    if ($plainHash -ne 'a8b923f7bac8ac2a00140cbaef7751bed13323318c1d96ef0ebc740286d1dac7') { throw "payload hash mismatch: $plainHash" }
    [IO.File]::WriteAllBytes($payloadZip, $plain)
    Expand-Archive -LiteralPath $payloadZip -DestinationPath $payloadDir -Force
    $payloadRoot = Join-Path $payloadDir 'zdb-pathstring-staticfiles-final-v2'
    if (-not (Test-Path -LiteralPath (Join-Path $payloadRoot 'run.ps1'))) { throw 'payload root invalid' }
    & pwsh -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $payloadRoot 'run.ps1') -Lane $Lane -EvidenceDir $evidence
    if ($LASTEXITCODE -ne 0) { throw "final PoC failed: $LASTEXITCODE" }
    $executeOutcome = 'success'
}
catch {
    $failureText = ($_ | Out-String)
    $failureText | Set-Content -LiteralPath (Join-Path $evidence 'failure.txt') -Encoding utf8NoBOM
}
finally {
    @("EXECUTE_OUTCOME=$executeOutcome","LANE=$Lane","SDK=$($entry.Sdk)","RUNTIME=$($entry.Runtime)","RUNNER=$Runner","RUN_ID=$RunId","SOURCE_SHA=$SourceSha") |
        Set-Content -LiteralPath (Join-Path $evidence 'workflow-receipt.txt') -Encoding ascii
    if ($null -ne $payloadKey -and $payloadKey.Length -eq 32) {
        Compress-Archive -Path (Join-Path $evidence '*') -DestinationPath $plainEvidenceZip -CompressionLevel Optimal -Force
        $evidencePlain = [IO.File]::ReadAllBytes($plainEvidenceZip)
        $evidenceIv = [Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
        $aes = [Security.Cryptography.Aes]::Create()
        try {
            $aes.Mode = [Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
            $aes.Key = $payloadKey
            $aes.IV = $evidenceIv
            $enc = $aes.CreateEncryptor()
            try { $evidenceCipher = $enc.TransformFinalBlock($evidencePlain, 0, $evidencePlain.Length) }
            finally { $enc.Dispose() }
        }
        finally { $aes.Dispose() }
        New-Item -ItemType Directory -Force -Path $sealedOut | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $sealedOut 'evidence.enc'), $evidenceCipher)
        [Convert]::ToHexString($evidenceIv).ToLowerInvariant() | Set-Content -LiteralPath (Join-Path $sealedOut 'evidence.iv.hex') -Encoding ascii
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($evidencePlain)).ToLowerInvariant() | Set-Content -LiteralPath (Join-Path $sealedOut 'evidence.plain.sha256') -Encoding ascii
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($evidenceCipher)).ToLowerInvariant() | Set-Content -LiteralPath (Join-Path $sealedOut 'evidence.cipher.sha256') -Encoding ascii
        Get-Content -LiteralPath (Join-Path $evidence 'workflow-receipt.txt') | Set-Content -LiteralPath (Join-Path $sealedOut 'metadata.txt') -Encoding ascii
    }
    Remove-Item -LiteralPath $payloadZip,$payloadDir,$runtimeKeyPath,$plainEvidenceZip,$evidence -Recurse -Force -ErrorAction SilentlyContinue
    if ($null -ne $payloadKey) { [Array]::Clear($payloadKey,0,$payloadKey.Length) }
    if ($null -ne $privatePemBytes) { [Array]::Clear($privatePemBytes,0,$privatePemBytes.Length) }
    if ($null -ne $wrappingKey) { [Array]::Clear($wrappingKey,0,$wrappingKey.Length) }
}
if ($executeOutcome -ne 'success') { throw "The final private PoC failed. $failureText" }
