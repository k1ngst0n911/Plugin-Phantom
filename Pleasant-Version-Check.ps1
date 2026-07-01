[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$BaseUrl = 'https://40808347.pleasantpassworddemo.com',

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$VendorIndexUrl = 'https://pleasantpasswords.com/info/pleasant-password-server/z-release-notes/older-and-in-between-versions',

  [Parameter(Mandatory = $false)]
  [ValidateRange(5, 120)]
  [int]$TimeoutSec = 20,

  [Parameter(Mandatory = $false)]
  [switch]$SelfTest,

  [Parameter(Mandatory = $false)]
  [switch]$SkipFingerprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# "KB-like" cache for this run
$script:Cache = @{}

function Normalize-Version {
  param([Parameter(Mandatory)][string]$Text)

  $t = $Text.Trim()
  $t = $t -replace '^[vV]\s*', ''

  $m = [regex]::Match($t, '^(?<v>\d+(?:\.\d+){1,3})')
  if (-not $m.Success) {
    throw "Normalize-Version: could not parse version from '$Text'"
  }

  $v = $m.Groups['v'].Value
  $parts = $v.Split('.')
  while ($parts.Count -lt 4) { $parts += '0' }

  return [version]($parts -join '.')
}

function Get-HttpResponse {
  param(
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][int]$TimeoutSec
  )

  Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec $TimeoutSec
}

function Get-HttpContent {
  param(
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][int]$TimeoutSec
  )

  $resp = Get-HttpResponse -Uri $Uri -TimeoutSec $TimeoutSec
  return ($resp.Content ?? '').ToString()
}

function Confirm-PleasantFingerprint {
  param(
    [Parameter(Mandatory)][string]$BaseUrl
  )

  if ($SkipFingerprint) { return }

  $rootUri = $BaseUrl.TrimEnd('/') + '/'
  $verUri  = $BaseUrl.TrimEnd('/') + '/Version'

  $root = ''
  try { $root = Get-HttpContent -Uri $rootUri -TimeoutSec $TimeoutSec } catch { $root = '' }

  $ver  = Get-HttpContent -Uri $verUri -TimeoutSec $TimeoutSec

  # Must have Build: version somewhere
  $hasBuild = [regex]::IsMatch($ver, 'Build:\s*\d+(?:\.\d+){2,3}', 'IgnoreCase')

  # Prefer product markers in either root or version response
  $markers = @(
    'Pleasant',
    'Password\s*Server',
    'pleasantpassword'
  )
  $hasMarker = $false
  foreach ($pat in $markers) {
    if ([regex]::IsMatch($ver, $pat, 'IgnoreCase') -or ($root -and [regex]::IsMatch($root, $pat, 'IgnoreCase'))) {
      $hasMarker = $true
      break
    }
  }

  if (-not $hasBuild -or -not $hasMarker) {
    throw "Fingerprint failed. /Version did not convincingly identify Pleasant Password Server. Use -SkipFingerprint to bypass."
  }
}

function Get-PpsInstalledVersion {
  param([Parameter(Mandatory)][string]$BaseUrl)

  if ($script:Cache.ContainsKey('installed')) { return $script:Cache['installed'] }

  $uri = ($BaseUrl.TrimEnd('/') + '/Version')
  $content = Get-HttpContent -Uri $uri -TimeoutSec $TimeoutSec

  $m = [regex]::Match($content, 'Build:\s*(?<v>\d+(?:\.\d+){2,3})', 'IgnoreCase')
  if (-not $m.Success) {
    throw "Could not parse installed Build version from /Version response. Response was: $content"
  }

  $v = Normalize-Version $m.Groups['v'].Value
  $script:Cache['installed'] = $v
  return $v
}

function Get-PpsVendorStableVersion {
  param([Parameter(Mandatory)][string]$VendorIndexUrl)

  if ($script:Cache.ContainsKey('stable')) { return $script:Cache['stable'] }

  $html = Get-HttpContent -Uri $VendorIndexUrl -TimeoutSec $TimeoutSec

  $m = [regex]::Match(
    $html,
    'Version\s+v?(?<v>\d+(?:\.\d+){1,3})\s*\(Stable\)',
    'IgnoreCase'
  )

  if (-not $m.Success) {
    throw "Could not locate vendor STABLE version on index page. The page format may have changed."
  }

  $v = Normalize-Version $m.Groups['v'].Value
  $script:Cache['stable'] = $v
  return $v
}

function Invoke-SelfTest {
  Write-Host "Running SelfTest..." -ForegroundColor Cyan
  $cases = @(
    @{ Installed = '9.1.10'; Stable = '9.1.11'; Expect = -1 },
    @{ Installed = '9.1.11'; Stable = '9.1.11'; Expect =  0 },
    @{ Installed = '9.1.11.0'; Stable = '9.1.11'; Expect =  0 },
    @{ Installed = 'v9.1.12'; Stable = '9.1.11'; Expect =  1 },
    @{ Installed = '9.1.11-rc1'; Stable = '9.1.11'; Expect = 0 }
  )

  foreach ($c in $cases) {
    $i = Normalize-Version $c.Installed
    $s = Normalize-Version $c.Stable
    $cmp = if ($i -lt $s) { -1 } elseif ($i -gt $s) { 1 } else { 0 }
    if ($cmp -ne $c.Expect) {
      throw "SelfTest failed: Installed='$($c.Installed)' Stable='$($c.Stable)' expected=$($c.Expect) got=$cmp"
    }
  }
  Write-Host "SelfTest passed." -ForegroundColor Green
}

try {
  if ($SelfTest) { Invoke-SelfTest; exit 0 }

  Confirm-PleasantFingerprint -BaseUrl $BaseUrl

  $installed = Get-PpsInstalledVersion -BaseUrl $BaseUrl
  $stable    = Get-PpsVendorStableVersion -VendorIndexUrl $VendorIndexUrl

  Write-Host ("Installed Build : {0}" -f $installed)
  Write-Host ("Vendor Stable   : {0}" -f $stable)
  Write-Host ("Endpoint        : {0}" -f ($BaseUrl.TrimEnd('/') + '/Version'))
  Write-Host ("Vendor Index    : {0}" -f $VendorIndexUrl)

  if ($installed -lt $stable) {
    Write-Error ("OUTDATED/VULNERABLE: Installed {0} is older than Vendor Stable {1}" -f $installed, $stable)
    exit 1
  }

  Write-Host ("OK: Installed {0} is not older than Vendor Stable {1}" -f $installed, $stable)
  exit 0
}
catch {
  Write-Error ("UNKNOWN/ERROR: {0}" -f $_.Exception.Message)
  exit 2
}
