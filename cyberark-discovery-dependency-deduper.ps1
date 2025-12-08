	<# 
.SYNOPSIS
  Deduplicate alias domain discovery dependencies/usages in CyberArk Privilege Cloud.
	.DESCRIPTION
  Identifies dependencies/usages discovered against an alias domain (e.g., domain.edu)
  that duplicate authoritative ones (e.g., subdomain.domain.edu). Produces a dry-run
  plan and, if -Apply is used, merges useful settings into the authoritative entry
  and deletes the alias duplicate. All actions are logged with JSON snapshots.
	.NOTES
  - Tested against PVWA 12–14 style APIs; includes fallbacks for "Dependencies" vs "Usages".
  - Start with a scoped run (e.g., -SafeFilter) and review dry run output first.
  - You can supply the alias to authoritative domain name mapping via -AliasMapPath (JSON) or -AliasMap.

	.PARAMETER PVWAUrl
  Base PVWA URL, e.g. https://subdomain.privilegecloud.cyberark.cloud
	.PARAMETER Credential
  PSCredential for classic PVWA logon (AuthType: CyberArk, LDAP, etc.). Optional if -BearerToken supplied.
	.PARAMETER AuthType
  PVWA auth mechanism for classic logon: CyberArk (default), LDAP, RADIUS. Ignored if -BearerToken provided.
	.PARAMETER BearerToken
  Pre-acquired OAuth/JWT token. If provided, script uses it directly.
	.PARAMETER AliasMapPath
  Path to JSON file with alias to authoritative domain mappings. Example:
  { "domain.edu": "subdomain.domain.edu", "NETBIOS": "subdomain.domain.edu" }
	.PARAMETER AliasMap
  Hashtable for alias→authoritative mappings (alternative to AliasMapPath).

	.PARAMETER SafeFilter
  One or more Safe names to include. If omitted, all Safes are considered.
	.PARAMETER PlatformIdFilter
  One or more Platform IDs to include (e.g., WinDomain, WinServerLocal, UnixSSH). Optional.
	.PARAMETER AccountNameFilter
  Wildcard(s) (server/username) to client-side filter accounts. Optional.
	.PARAMETER OutDir
  Output folder for logs, CSVs, and JSON snapshots. Default: .\out
	.PARAMETER Apply
  When set, performs merges/deletes. Otherwise, dry-run only.
	.PARAMETER Force
  Skip confirmation prompts when -Apply.
	#>
	[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory=$true)][string]$PVWAUrl,
  [Parameter()][pscredential]$Credential,
  [Parameter()][string]$AuthType = "CyberArk",
  [Parameter()][string]$BearerToken,
  [Parameter()][string]$AliasMapPath,
  [Parameter()][hashtable]$AliasMap,
  [Parameter()][string[]]$SafeFilter,
  [Parameter()][string[]]$PlatformIdFilter,
  [Parameter()][string[]]$AccountNameFilter,
  [Parameter()][string]$OutDir = ".\out",
  [Parameter()][switch]$Apply,
  [Parameter()][switch]$Force,
  [Parameter()][int]$PageSize = 100,
  [Parameter()][int]$TimeoutSec = 60,
  [Parameter()][switch]$VerboseRest,
  [Parameter()][switch]$SkipCertValidation
)
	Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
	#region Helpers ----------------------------------------------------------------
	if ($SkipCertValidation) {
  try {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
  public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
  } catch {}
}
	$null = New-Item -ItemType Directory -Force -Path $OutDir, (Join-Path $OutDir "raw"), (Join-Path $OutDir "archive") | Out-Null
$LogPath = Join-Path $OutDir "actions.log"
function Write-Log { param([string]$Message,[string]$Level="INFO")
  $line = "$(Get-Date -Format s) [$Level] $Message"
  $line | Tee-Object -FilePath $LogPath -Append | Out-Null
}
	function As-Array([object]$o) {
  if ($null -eq $o) { return @() }
  if ($o -is [System.Collections.IEnumerable] -and $o -isnot [string]) { return @($o) }
  return ,$o
}
function Get-Prop {
  param(
    [Parameter(Mandatory)][object]$Object,
    [Parameter(Mandatory)][string[]]$Names
  )
  if ($null -eq $Object) { return $null }

  $psobj = [psobject]$Object

  # 1st pass – direct properties on the object
  foreach ($name in $Names) {
    $prop = $psobj.PSObject.Properties[$name]
    if ($null -ne $prop -and $null -ne $prop.Value) {
      return $prop.Value
    }
  }

  # 2nd pass – platformAccountProperties (for dependentAccounts APIs)
  $platProp = $psobj.PSObject.Properties['platformAccountProperties']
  if ($platProp -and $platProp.Value) {
    $plat = $platProp.Value

    if ($plat -is [hashtable]) {
      foreach ($name in $Names) {
        if ($plat.ContainsKey($name) -and $null -ne $plat[$name]) {
          return $plat[$name]
        }
      }
    } else {
      $platPs = [psobject]$plat
      foreach ($name in $Names) {
        $inner = $platPs.PSObject.Properties[$name]
        if ($null -ne $inner -and $null -ne $inner.Value) {
          return $inner.Value
        }
      }
    }
  }
  return $null
}
	function Invoke-PVWARest {
  param(
    [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','PATCH','DELETE')] [string]$Method,
    [Parameter(Mandatory)][string]$Uri,
    [hashtable]$Headers,
    [object]$Body,
    [int]$Retry = 3
  )
  $attempt = 0
  do {
    try {
      if ($VerboseRest) { Write-Log "REST $Method $Uri" "DEBUG" }
      if ($Body) {
        $resp = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 50) -TimeoutSec $TimeoutSec
      } else {
        $resp = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec
      }
      return $resp
    } catch {
      $attempt++
      if ($attempt -ge $Retry) {
        Write-Log "REST $Method failed: $Uri `n$($_.Exception.Message)" "ERROR"
        throw
      } else {
        Start-Sleep -Seconds ([Math]::Min(2*$attempt,10))
      }
    }
  } while ($true)
}
	function Get-AuthHeaders {
  if ($BearerToken) {
    Write-Log "Using provided Bearer token"
    return @{ 'Authorization' = "Bearer $BearerToken" }
  }
  if (-not $Credential) { throw "Provide -BearerToken or -Credential." }
	$body = @{
    username = $Credential.UserName
    password = $Credential.GetNetworkCredential().Password
  }
	$candidates = @(
    "$PVWAUrl/PasswordVault/API/Auth/$AuthType/Logon",           # modern classic
    "$PVWAUrl/PasswordVault/API/Authentication/Logon",           # very old
    "$PVWAUrl/PasswordVault/API/Auth/LDAP/Logon"                 # fallback
  )
	foreach ($u in $candidates) {
    try {
      $tok = Invoke-RestMethod -Method POST -Uri $u -ContentType 'application/json' -Body ($body | ConvertTo-Json) -TimeoutSec $TimeoutSec
      if ($tok) {
        if ($tok -is [string]) {
          $tokenString = $tok
        } else {
          $tokenProp = $tok.PSObject.Properties['token']
          $tokenString = if ($tokenProp) { [string]$tokenProp.Value } else { [string]$tok }
        }
        return @{ 'Authorization' = "Bearer $tokenString"; 'X-Authorization' = $tokenString }
      }
    } catch {
      Write-Log "Auth attempt failed on ${u}: $($_.Exception.Message)" "WARN"
    }
  }
  throw "All logon endpoints failed. Check -PVWAUrl/-AuthType or provide -BearerToken."
}
	# Domain map (alias -> authoritative)
if ($AliasMapPath) {
  if (-not (Test-Path $AliasMapPath)) { throw "Alias map file not found: $AliasMapPath" }
  $AliasMap = Get-Content $AliasMapPath -Raw | ConvertFrom-Json -AsHashtable
}
if (-not $AliasMap) {
  # Minimal sample; replace with your own mapping or pass -AliasMap/-AliasMapPath
  $AliasMap = @{
    "domain.edu" = "subdomain.domain.edu"
  }
}
$AliasSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$null = $AliasMap.Keys | ForEach-Object { [void]$AliasSet.Add($_) }
	function Map-Domain([string]$d) {
  if ([string]::IsNullOrWhiteSpace($d)) { return $d }
  if ($AliasMap.ContainsKey($d)) { return $AliasMap[$d] }
  return $d
}
	function Normalize-User([string]$u) {
  if ([string]::IsNullOrWhiteSpace($u)) { return $u }
  $ux = $u.Trim()
  if ($ux -match '^(?<dom>[^\\]+)\\(?<name>.+)$') { return $Matches['name'].ToLower() }
  if ($ux -match '^(?<name>[^@]+)@(?<dom>.+)$') { return $Matches['name'].ToLower() }
  return $ux.ToLower()
}
	function Lower([string]$s){ if ($null -eq $s) { return $null } return $s.ToLower() }
	# Extracts type-specific identifiers to build a stable join key
function Get-CanonicalIdentifiers {
  param([object]$Dep)

  # Keys vary by dependency type & PVWA version. We try common patterns.
  $type    = Get-Prop $Dep @('Type','UsageType','DependencyType','platformId')
  $machine = Get-Prop $Dep @('MachineName','ComputerName','Target','Address','ComputerDnsName','HostName')
  $service = Get-Prop $Dep @('ServiceName')
  $task    = Get-Prop $Dep @('TaskPath','TaskName')
  $iisApp  = Get-Prop $Dep @('Application','AppName')
  $iisPool = Get-Prop $Dep @('AppPool','ApplicationPool')
  $site    = Get-Prop $Dep @('Site','SiteName')
  $exe     = Get-Prop $Dep @('BinaryPathName','ExecutablePath')
  $name    = Get-Prop $Dep @('Name','DisplayName','Id','ID','DependencyID','UsageID','dependentAccountId')

  $obj =
    if     ($service)                     { $service }
    elseif ($task)                        { $task }
    elseif ($iisApp -or $iisPool -or $site) { "$iisPool|$site|$iisApp" }
    elseif ($exe)                         { $exe }
    else                                  { $name }

  [pscustomobject]@{
    Type    = "$type"
    Machine = "$machine"
    Object  = "$obj"
  }
}
	# Build dedupe key (domain intentionally omitted; user normalized)
function Build-JoinKey {
  param(
    [object]$Dep,
    [string]$NormalizedUser
  )
  $ci = Get-CanonicalIdentifiers -Dep $Dep
  $parts = @(
    (Lower $ci.Type),
    (Lower $ci.Machine),
    (Lower $ci.Object),
    $NormalizedUser
  )
  return ($parts -join '|')
}
	# Returns a reduced-property hashtable for diff (ignores IDs/timestamps)
$IgnoreProps = @('Id','ID','DependencyID','UsageID','AccountId','AccountID','Created','CreationTime','LastModified','LastUpdate','Address','ComputerDnsName','MachineName','Target','HostName','DisplayName','Name','PlatformId','SafeName')
function Get-ComparableProps {
  param([hashtable]$Dep)
  $ht = @{}
  foreach ($k in $Dep.Keys) {
    if ($IgnoreProps -contains $k) { continue }
    $val = $Dep[$k]
    if ($null -eq $val) { continue }
    # Keep scalars and simple arrays only
    if ($val -is [string] -or $val -is [int] -or $val -is [bool] -or $val -is [double]) {
      $ht[$k] = $val
    } elseif ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
      $ht[$k] = @($val)
    }
  }
  return $ht
}
	function Diff-Props {
  param([hashtable]$From, [hashtable]$To)
  $delta = @{}
  foreach ($k in $From.Keys) {
    if (-not $To.ContainsKey($k)) { $delta[$k] = $From[$k]; continue }
    $a = $From[$k]; $b = $To[$k]
    if ($a -is [System.Collections.IEnumerable] -and $a -isnot [string]) {
      if (@($a) -join '|') { } # normalize
      if ((@($a) -join '|') -ne (@($b) -join '|')) { $delta[$k] = $From[$k] }
    } else {
      if ("$a" -ne "$b") { $delta[$k] = $From[$k] }
    }
  }
  return $delta
}
	#endregion Helpers --------------------------------------------------------------
	$Headers = Get-AuthHeaders
	# GET all accounts (paged). We’ll filter client-side for safety across PVWA versions.
Write-Log "Collecting accounts..."
$Accounts = @()
$offset = 0
do {
  $u = "$PVWAUrl/PasswordVault/API/Accounts?limit=$PageSize&offset=$offset"
  $resp = Invoke-PVWARest -Method GET -Uri $u -Headers $Headers
  $batch = @()
  if ($resp -and $resp.value) { $batch = As-Array $resp.value }
  elseif ($resp -and $resp.Accounts) { $batch = As-Array $resp.Accounts }
  elseif ($resp -is [System.Collections.IEnumerable]) { $batch = As-Array $resp }
  else { $batch = @() }

  foreach ($a in $batch) {
    # normalize common fields (case-insensitive, StrictMode-safe)
    $acctId       = Get-Prop $a @('id','Id','AccountID')
    $acctName     = Get-Prop $a @('Name','name','UserName','userName')
    $acctSafe     = Get-Prop $a @('SafeName','safeName')
    $acctPlatform = Get-Prop $a @('PlatformId','platformId')
    $acctAddress  = Get-Prop $a @('address','Address')
    $acctUser     = Get-Prop $a @('UserName','userName')

  $acc = [pscustomobject]@{
    Id         = $acctId
    Name       = $acctName ?? $acctAddress
    SafeName   = $acctSafe
    PlatformId = $acctPlatform
    Address    = $acctAddress
    UserName   = $acctUser
  }
  $Accounts += $acc
}

	$count = $batch.Count
  $offset += $PageSize
  Write-Log "Fetched $count accounts (offset=$offset)" "DEBUG"
} while ($count -eq $PageSize)
	# Client-side filters
if ($SafeFilter) {
  $Accounts = $Accounts | Where-Object { $SafeFilter -contains $_.SafeName }
}
if ($PlatformIdFilter) {
  $Accounts = $Accounts | Where-Object { $PlatformIdFilter -contains $_.PlatformId }
}
if ($AccountNameFilter) {
  $Accounts = $Accounts | Where-Object {
    $acctName = "$($_.Name) $($_.UserName) $($_.Address)"
    foreach ($w in $AccountNameFilter) { if ($acctName -like $w) { return $true } }
    return $false
  }
}
	Write-Log "Accounts in scope: $($Accounts.Count)"
  #TODO REMOVE AFTER TESTING
  if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
    $resp | ConvertTo-Json -Depth 5 | Out-File "$OutDir\accounts-raw.json"
    ($resp.value ?? $resp.Accounts ?? $resp) |
    Select-Object -First 1 |
    ConvertTo-Json -Depth 5 |
    Out-File "$OutDir\accounts-first.json"
  #TODO REMOVE AFTER TESTING
	# Pull dependencies/usages for each account
$AllDeps = @()
foreach ($acct in $Accounts) {
  if (-not $acct.Id) { continue }
  $depUri0 = "$PVWAUrl/PasswordVault/API/Accounts/$($acct.Id)/dependentAccounts"
  $depUri1 = "$PVWAUrl/PasswordVault/API/Accounts/$($acct.Id)/Dependencies"
  $depUri2 = "$PVWAUrl/PasswordVault/API/Accounts/$($acct.Id)/Usages"
  $deps = @()

  try {
    # Preferred modern endpoint (Self-Hosted 12+/Privilege Cloud)
    $r = Invoke-PVWARest -Method GET -Uri $depUri0 -Headers $Headers
    $deps = As-Array ($r.value ?? $r)
  } catch {
    Write-Log "dependentAccounts endpoint failed for $($acct.Id). Trying legacy /Dependencies..." "WARN"
    try {
      $r = Invoke-PVWARest -Method GET -Uri $depUri1 -Headers $Headers
      $deps = As-Array ($r.value ?? $r.Dependencies ?? $r)
    } catch {
      Write-Log "Dependencies endpoint failed for $($acct.Id). Trying /Usages..." "WARN"
      try {
        $r = Invoke-PVWARest -Method GET -Uri $depUri2 -Headers $Headers
        $deps = As-Array ($r.value ?? $r.Usages ?? $r)
      } catch {
        Write-Log "All dependency endpoints failed for $($acct.Id): $($_.Exception.Message)" "ERROR"
        continue
      }
    }
  }
	# Save raw snapshot
  $rawPath = Join-Path $OutDir "raw\acct_$($acct.Id).json"
  ($deps | ConvertTo-Json -Depth 50) | Out-File -Encoding UTF8 $rawPath
  foreach ($d in $deps) {
    # capture raw as hashtable for diffing/snapshots
    $h = @{}
    foreach ($p in $d.PSObject.Properties.Name) { $h[$p] = $d.$p }

    # derive logon domain/username from original PSObject
    $domain = Get-Prop $d @('LogonDomain','Domain','AccountDomain')
    $user   = Get-Prop $d @('LogonUser','User','UserName','AccountName')

    $canon  = Get-CanonicalIdentifiers -Dep $d

    $AllDeps += [pscustomobject]@{
      AccountId         = $acct.Id
      SafeName          = $acct.SafeName
      AccountName       = $acct.Name
      PlatformId        = $acct.PlatformId
      DependencyId      = $h['Id'] ?? $h['ID'] ?? $h['DependencyID'] ?? $h['UsageID']
      Raw               = $h
      Type              = $canon.Type
      Machine           = $canon.Machine
      ObjectName        = $canon.Object
      DomainOriginal    = $domain
      DomainMapped      = Map-Domain $domain
      UserOriginal      = $user
      UserNormalized    = Normalize-User $user
      JoinKey           = Build-JoinKey -Dep $d -NormalizedUser (Normalize-User $user)
    }
  }
}
	Write-Log "Dependencies/usages collected: $($AllDeps.Count)"
	# Identify duplicates: same Account + JoinKey but different domain strings (alias vs authoritative)
$groups = $AllDeps | Group-Object -Property AccountId, JoinKey
$Candidates = @()
	foreach ($g in $groups) {
  $items = $g.Group
  if ($items.Count -lt 2) { continue }
	# Partition by whether domain is alias
  $alias = $items | Where-Object { $_.DomainOriginal -and $AliasSet.Contains($_.DomainOriginal) }
  if ($alias.Count -eq 0) { continue }
	$auth = $items | Where-Object { $_.DomainMapped -and ($_.DomainMapped -eq $_.DomainOriginal) } # original already authoritative
  if ($auth.Count -eq 0) {
    # No explicit authoritative entry; skip (or consider converting alias → authoritative)
    continue
  }

	# Choose the first authoritative as the keeper
  $keeper = $auth | Select-Object -First 1
	foreach ($dup in $alias) {
    # Compute config delta (alias minus keeper)
    $from = Get-ComparableProps -Dep $dup.Raw
    $to   = Get-ComparableProps -Dep $keeper.Raw
    $delta = Diff-Props -From $from -To $to
	$Candidates += [pscustomobject]@{
      SafeName       = $dup.SafeName
      AccountId      = $dup.AccountId
      AccountName    = $dup.AccountName
      PlatformId     = $dup.PlatformId
      Type           = $dup.Type
      Machine        = $dup.Machine
      ObjectName     = $dup.ObjectName
      JoinKey        = $dup.JoinKey
      AliasDomain    = $dup.DomainOriginal
      Authoritative  = $keeper.DomainOriginal
      AliasDepId     = $dup.DependencyId
      KeeperDepId    = $keeper.DependencyId
      DeltaProps     = $delta
      AliasRaw       = $dup.Raw
      KeeperRaw      = $keeper.Raw
    }
  }
}
	# Emit dry-run CSV
$dry = $Candidates | Select-Object SafeName,AccountId,AccountName,PlatformId,Type,Machine,ObjectName,JoinKey,AliasDomain,Authoritative,AliasDepId,KeeperDepId,
  @{n='DeltaPropsJson';e={ ($_."DeltaProps" | ConvertTo-Json -Depth 20 -Compress) }}
	$DryPath = Join-Path $OutDir "dry-run.csv"
$dry | Export-Csv -NoTypeInformation -Encoding UTF8 $DryPath
Write-Log "Dry-run written: $DryPath"
Write-Output "Dry-run path: $DryPath"
Write-Output ("Found {0} alias duplicates across {1} accounts" -f ($Candidates.Count), (($Candidates | Select-Object -Expand AccountId | Sort-Object -Unique).Count))
	if (-not $Apply) {
  Write-Output "Analysis complete. Re-run with -Apply (and optionally -Force) to perform merges/deletes."
  return
}
	if (-not $Force) {
  $confirm = Read-Host "About to MERGE and DELETE $($Candidates.Count) alias dependencies. Type 'YES' to continue"
  if ($confirm -ne 'YES') {
    Write-Output "Aborted by user."
    return
  }
}
	# Try to update keeper with delta (best-effort), then delete alias
function Update-Dependency {
  param(
    [Parameter(Mandatory)][string]$AccountId,
    [Parameter(Mandatory)][string]$DepId,
    [Parameter(Mandatory)][hashtable]$NewProps
  )
  if ($NewProps.Keys.Count -eq 0) { return $true }
  $payload = @{}
  foreach ($k in $NewProps.Keys) { $payload[$k] = $NewProps[$k] }

  $u0 = "$PVWAUrl/PasswordVault/API/Accounts/$AccountId/dependentAccounts/$DepId"
  $u1 = "$PVWAUrl/PasswordVault/API/Accounts/$AccountId/Dependencies/$DepId"
  $u2 = "$PVWAUrl/PasswordVault/API/Accounts/$AccountId/Usages/$DepId"

  # Preferred: dependentAccounts API
  try {
    $null = Invoke-PVWARest -Method PUT -Uri $u0 -Headers $Headers -Body $payload
    Write-Log "Merged props into keeper via PUT dependentAccounts: acct=$AccountId dep=$DepId keys=[$(($payload.Keys -join ','))]"
    return $true
  } catch {
    Write-Log "PUT /dependentAccounts failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "WARN"
  }

  # Legacy fallbacks: /Dependencies then /Usages
  try {
    $null = Invoke-PVWARest -Method PUT -Uri $u1 -Headers $Headers -Body $payload
    Write-Log "Merged props into keeper via PUT Dependencies: acct=$AccountId dep=$DepId keys=[$(($payload.Keys -join ','))]"
    return $true
  } catch {
    Write-Log "PUT /Dependencies failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "WARN"
    try {
      $null = Invoke-PVWARest -Method PATCH -Uri $u1 -Headers $Headers -Body $payload
      Write-Log "Merged props into keeper via PATCH Dependencies: acct=$AccountId dep=$DepId"
      return $true
    } catch {
      Write-Log "PATCH /Dependencies failed: $($_.Exception.Message)" "WARN"
      try {
        $null = Invoke-PVWARest -Method PUT -Uri $u2 -Headers $Headers -Body $payload
        Write-Log "Merged props via PUT Usages: acct=$AccountId dep=$DepId"
        return $true
      } catch {
        Write-Log "PUT /Usages failed: $($_.Exception.Message)" "WARN"
        try {
          $null = Invoke-PVWARest -Method PATCH -Uri $u2 -Headers $Headers -Body $payload
          Write-Log "Merged props via PATCH Usages: acct=$AccountId dep=$DepId"
          return $true
        } catch {
          Write-Log "All merge attempts failed for acct=$AccountId dep=$DepId" "ERROR"
          return $false
        }
      }
    }
  }
}
	function Delete-Dependency {
  param(
    [Parameter(Mandatory)][string]$AccountId,
    [Parameter(Mandatory)][string]$DepId,
    [Parameter(Mandatory)][hashtable]$AliasRaw
  )
  # archive alias JSON first
  $stamp = Get-Date -Format "yyyyMMdd_HHmmssfff"
  $arch = Join-Path $OutDir ("archive\alias_acct{0}_dep{1}_{2}.json" -f $AccountId,$DepId,$stamp)
  ($AliasRaw | ConvertTo-Json -Depth 50) | Out-File -Encoding UTF8 $arch
  $u0 = "$PVWAUrl/PasswordVault/API/Accounts/$AccountId/dependentAccounts/$DepId"
  $u1 = "$PVWAUrl/PasswordVault/API/Accounts/$AccountId/Dependencies/$DepId"
  $u2 = "$PVWAUrl/PasswordVault/API/Accounts/$AccountId/Usages/$DepId"

  # Preferred: dependentAccounts
  try {
    $null = Invoke-PVWARest -Method DELETE -Uri $u0 -Headers $Headers
    Write-Log "Deleted alias via dependentAccounts endpoint: acct=$AccountId dep=$DepId"
    return $true
  } catch {
    Write-Log "DELETE /dependentAccounts failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "WARN"
  }

  # Legacy fallbacks
  try {
    $null = Invoke-PVWARest -Method DELETE -Uri $u1 -Headers $Headers
    Write-Log "Deleted alias via Dependencies endpoint: acct=$AccountId dep=$DepId"
    return $true
  } catch {
    Write-Log "DELETE /Dependencies failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "WARN"
    try {
      $null = Invoke-PVWARest -Method DELETE -Uri $u2 -Headers $Headers
      Write-Log "Deleted alias via Usages endpoint: acct=$AccountId dep=$DepId"
      return $true
    } catch {
      Write-Log "DELETE /Usages failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "ERROR"
      return $false
    }
  }
}
	# Execute plan
$success = 0
$merged  = 0
$deleted = 0
	foreach ($row in $Candidates) {
  $acctId   = $row.AccountId
  $aliasDep = $row.AliasDepId
  $keepDep  = $row.KeeperDepId
	# Merge keeper with alias delta
  $delta = $row.DeltaProps
  $mergedOk = $true
  if ($delta -and $delta.Keys.Count -gt 0) {
    $mergedOk = Update-Dependency -AccountId $acctId -DepId $keepDep -NewProps $delta
    if ($mergedOk) { $merged++ }
  }
	# Delete alias duplicate
  $delOk = Delete-Dependency -AccountId $acctId -DepId $aliasDep -AliasRaw $row.AliasRaw
  if ($delOk) { $deleted++ }
	if ($mergedOk -and $delOk) { $success++ }
}
	Write-Log "Merge attempts: $merged, Deletes: $deleted, Success pairs: $success"
	# Post-state verify for touched accounts
$Touched = $Candidates | Select-Object -Expand AccountId -Unique
$Post = @()
foreach ($acctId in $Touched) {
  $depUri0 = "$PVWAUrl/PasswordVault/API/Accounts/$acctId/dependentAccounts"
  $depUri1 = "$PVWAUrl/PasswordVault/API/Accounts/$acctId/Dependencies"
  $depUri2 = "$PVWAUrl/PasswordVault/API/Accounts/$acctId/Usages"
  $deps = @()
  try {
    $r = Invoke-PVWARest -Method GET -Uri $depUri0 -Headers $Headers
    $deps = As-Array ($r.value ?? $r)
  } catch {
    try {
      $r = Invoke-PVWARest -Method GET -Uri $depUri1 -Headers $Headers
      $deps = As-Array ($r.value ?? $r.Dependencies ?? $r)
    } catch {
      try {
        $r = Invoke-PVWARest -Method GET -Uri $depUri2 -Headers $Headers
        $deps = As-Array ($r.value ?? $r.Usages ?? $r)
      } catch {
        Write-Log "Post-verify failed for acct=${acctId}: $($_.Exception.Message)" "ERROR"
        continue
      }
    }
  }
  foreach ($d in $deps) {
    # raw snapshot as hashtable (if you want to inspect later)
    $h = @{}
    foreach ($p in $d.PSObject.Properties.Name) { $h[$p] = $d.$p }

    $domain = Get-Prop $d @('LogonDomain','Domain','AccountDomain')
    $user   = Get-Prop $d @('LogonUser','User','UserName','AccountName')
    $canon  = Get-CanonicalIdentifiers -Dep $d

    $Post += [pscustomobject]@{
      AccountId    = $acctId
      DepId        = $h['Id'] ?? $h['ID'] ?? $h['DependencyID'] ?? $h['UsageID']
      Type         = "$($canon.Type)"
      Machine      = "$($canon.Machine)"
      ObjectName   = "$($canon.Object)"
      Domain       = "$domain"
      User         = "$user"
      JoinKey      = Build-JoinKey -Dep $d -NormalizedUser (Normalize-User $user)
    }
  }
}
	$PostPath = Join-Path $OutDir "post-state.csv"
$Post | Export-Csv -NoTypeInformation -Encoding UTF8 $PostPath
Write-Log "Post-state written: $PostPath"
Write-Output "Done. Merged: $merged; Deleted: $deleted; Success pairs: $success"
Write-Output "Post-state: $PostPath"