param(
    [Parameter(Mandatory = $true)][string]$PayloadPrefix,
    [Parameter(Mandatory = $true)][string]$EvidenceFilter,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$Metadata = ''
)

$ErrorActionPreference = 'Stop'
$keyPath = Join-Path $PWD "$PayloadPrefix.runtime.key"
if (-not (Test-Path -LiteralPath $keyPath)) { throw 'evidence key unavailable' }

$searchRoots = @(
    $PWD.Path,
    $env:GITHUB_WORKSPACE,
    $env:RUNNER_TEMP,
    $(if ($env:GITHUB_WORKSPACE) { Split-Path -Parent $env:GITHUB_WORKSPACE })
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

$found = foreach ($root in $searchRoots) {
    Get-ChildItem -LiteralPath $root -Directory -Filter $EvidenceFilter -Recurse -ErrorAction SilentlyContinue
}
$dirs = @($found | Sort-Object -Property FullName -Unique)
if ($dirs.Count -eq 0) { throw "NO_EVIDENCE_DIRECTORY filter=$EvidenceFilter roots=$($searchRoots -join ';')" }

$zipPath = Join-Path $PWD 'evidence.plain.zip'
Compress-Archive -Path $dirs.FullName -DestinationPath $zipPath -Force
$plainHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash.ToLowerInvariant()
$payloadKey = [IO.File]::ReadAllBytes($keyPath)
$evidenceIv = [Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
$plain = [IO.File]::ReadAllBytes($zipPath)

$aes = [Security.Cryptography.Aes]::Create()
try {
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $payloadKey
    $aes.IV = $evidenceIv
    $encryptor = $aes.CreateEncryptor()
    try { $cipher = $encryptor.TransformFinalBlock($plain, 0, $plain.Length) }
    finally { $encryptor.Dispose() }
}
finally { $aes.Dispose() }

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$cipherPath = Join-Path $OutputDirectory 'evidence.enc'
[IO.File]::WriteAllBytes($cipherPath, $cipher)
[Convert]::ToHexString($evidenceIv).ToLowerInvariant() | Set-Content (Join-Path $OutputDirectory 'evidence.iv.hex') -Encoding ascii
$plainHash | Set-Content (Join-Path $OutputDirectory 'evidence.plain.sha256') -Encoding ascii
(Get-FileHash -Algorithm SHA256 -LiteralPath $cipherPath).Hash.ToLowerInvariant() | Set-Content (Join-Path $OutputDirectory 'evidence.cipher.sha256') -Encoding ascii
@('FORMAT=ZDB-AES-256-CBC-PKCS7-V1', $Metadata, "EVIDENCE_COUNT=$($dirs.Count)") | Set-Content (Join-Path $OutputDirectory 'metadata.txt') -Encoding ascii

Remove-Item -LiteralPath $zipPath,$keyPath -Force -ErrorAction SilentlyContinue
foreach ($dir in $dirs) { Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue }
