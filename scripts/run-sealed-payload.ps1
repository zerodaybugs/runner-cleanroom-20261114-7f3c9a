param(
    [Parameter(Mandatory = $true)][string]$PayloadPrefix,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($env:WRAPPING_KEY_B64)) { throw 'wrapping key missing' }

$wrappingKey = [Convert]::FromBase64String($env:WRAPPING_KEY_B64)
if ($wrappingKey.Length -ne 32) { throw 'wrapping key length invalid' }
$wrappedPrivate = [IO.File]::ReadAllBytes((Join-Path $PWD 'bootstrap/private.pem.enc'))
$wrapIv = [Convert]::FromHexString((Get-Content -LiteralPath (Join-Path $PWD 'bootstrap/private.iv.hex') -Raw).Trim())

$aes = [Security.Cryptography.Aes]::Create()
try {
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $wrappingKey
    $aes.IV = $wrapIv
    $decryptor = $aes.CreateDecryptor()
    try { $privatePemBytes = $decryptor.TransformFinalBlock($wrappedPrivate, 0, $wrappedPrivate.Length) }
    finally { $decryptor.Dispose() }
}
finally { $aes.Dispose() }

$rsa = [Security.Cryptography.RSA]::Create()
try {
    $rsa.ImportFromPem([Text.Encoding]::ASCII.GetString($privatePemBytes))
    $wrappedPayloadKey = [Convert]::FromBase64String((Get-Content -LiteralPath (Join-Path $PWD "$PayloadPrefix.key.enc.b64") -Raw).Trim())
    $payloadKey = $rsa.Decrypt($wrappedPayloadKey, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
}
finally { $rsa.Dispose() }
if ($payloadKey.Length -ne 32) { throw 'payload key length invalid' }
[IO.File]::WriteAllBytes((Join-Path $PWD "$PayloadPrefix.runtime.key"), $payloadKey)

$payloadIv = [Convert]::FromHexString((Get-Content -LiteralPath (Join-Path $PWD "$PayloadPrefix.iv.hex") -Raw).Trim())
$payloadCipher = [Convert]::FromBase64String((Get-Content -LiteralPath (Join-Path $PWD "$PayloadPrefix.enc.b64") -Raw).Trim())
$aes = [Security.Cryptography.Aes]::Create()
try {
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $payloadKey
    $aes.IV = $payloadIv
    $decryptor = $aes.CreateDecryptor()
    try { $payloadPlain = $decryptor.TransformFinalBlock($payloadCipher, 0, $payloadCipher.Length) }
    finally { $decryptor.Dispose() }
}
finally { $aes.Dispose() }

[IO.File]::WriteAllBytes($OutputPath, $payloadPlain)
$expectedHash = (Get-Content -LiteralPath (Join-Path $PWD "$PayloadPrefix.plain.sha256") -Raw).Trim().ToLowerInvariant()
$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $OutputPath).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) { throw 'payload hash mismatch' }
