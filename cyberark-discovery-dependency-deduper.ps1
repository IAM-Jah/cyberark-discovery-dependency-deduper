	<# 
.SYNOPSIS
  Deduplicate alias domain discovery dependencies/usages in CyberArk Privilege Cloud.
	.DESCRIPTION
  Identifies dependencies/usages discovered against an alias domain (e.g., domain.edu)
  that duplicate authoritative ones (e.g., subdomain.domain.edu). Produces a dry-run
  plan and, if -Apply is used, merges useful settings into the authoritative entry
  and deletes the alias duplicate. All actions are logged with JSON snapshots.
	.NOTES
  - Supports only: ISPSS /api/accounts/{id}/account-dependents and Self-Hosted /PasswordVault/API/Accounts/{id}/dependentAccounts.
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
  Hashtable for alias to authoritative mappings (alternative to AliasMapPath).
	.PARAMETER SafeFilter
  One or more Safe names to include. If omitted, all Safes are considered.
	.PARAMETER PlatformIdFilter
  One or more Platform IDs to include (e.g., WinDomain, WinServerLocal, UnixSSH). Optional.
	.PARAMETER AccountNameFilter
  Wildcard(s) (server/username) to client-side filter accounts. Optional.
	.PARAMETER OutDir
  Output folder for logs, CSVs, and JSON snapshots. Default: .\out\YYYYMMDD_HHMMSS
	.PARAMETER Apply
  When set, performs merges/deletes. Otherwise, dry-run only.
	.PARAMETER Force
  Skip confirmation prompts when -Apply.
	.PARAMETER PlanOnly
  Always run in dry-run mode, even if -Apply is specified.
	.PARAMETER ResumeFrom
  Path to a prior dry-run CSV; replays only those rows.
	.PARAMETER OnlyMergeKeys
  Optional list of delta keys (supports wildcards) to merge. Example: platformDependentProperties.restartService
	.PARAMETER Parallel
  Fetch account dependents in parallel (PowerShell 7+ only).
	.PARAMETER ThrottleLimit
  Maximum number of parallel tasks when -Parallel is set.
	.PARAMETER AccountRetry
  Additional per-account retry attempts for dependents GET (in addition to per-call retries).
	.PARAMETER MaxMerges
  Maximum number of merge updates to perform in a run (0 = unlimited).
	.PARAMETER MaxDeletes
  Maximum number of deletes to perform in a run (0 = unlimited).
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
  [Parameter()][string]$OutDir,
  [Parameter()][switch]$Apply,
  [Parameter()][switch]$Force,
  [Parameter()][switch]$PlanOnly,
  [Parameter()][string]$ResumeFrom,
  [Parameter()][string[]]$OnlyMergeKeys,
  [Parameter()][switch]$Parallel,
  [Parameter()][int]$ThrottleLimit = 4,
  [Parameter()][int]$AccountRetry = 0,
  [Parameter()][int]$MaxMerges = 0,
  [Parameter()][int]$MaxDeletes = 0,
  [Parameter()][int]$PageSize = 100,
  [Parameter()][int]$TimeoutSec = 60,
  [Parameter()][switch]$VerboseRest,
  [Parameter()][switch]$SkipCertValidation
)
$script:DependentsApiFlavor = 'ISPSS'      # or 'SelfHosted'
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
	if ([string]::IsNullOrWhiteSpace($OutDir)) {
  $OutDir = Join-Path "." ("out\" + (Get-Date -Format "yyyyMMdd_HHmmss"))
}
	$null = New-Item -ItemType Directory -Force -Path $OutDir, (Join-Path $OutDir "raw"), (Join-Path $OutDir "archive") | Out-Null
$LogPath = Join-Path $OutDir "actions.log"
$ErrorLogPath = Join-Path $OutDir "errors.jsonl"
	if ($PlanOnly) {
  $Apply = $false
  Write-Log "PlanOnly set; Apply disabled." "INFO"
}

# Choose which dependents endpoint to use: 'ISPSS', 'SelfHosted', or 'Auto'
if (-not $script:DependentsApiFlavor) { $script:DependentsApiFlavor = 'Auto' }

function Get-DependentsApiFlavor {
  param([Parameter(Mandatory)][string]$PVWAUrl)

  switch ($script:DependentsApiFlavor) {
    'ISPSS'      { return 'ISPSS' }
    'SelfHosted' { return 'SelfHosted' }
    default {
      if ($PVWAUrl -match 'privilegecloud\.cyberark\.cloud$') { return 'ISPSS' }
      return 'SelfHosted'
    }
  }
}

function Get-AccountDependentsUri {
  param(
    [Parameter(Mandatory)][string]$PVWAUrl,
    [Parameter(Mandatory)][string]$AccountId,
    [string]$DepId
  )

  $baseUrl = $PVWAUrl.TrimEnd('/')
  $acctEsc = [uri]::EscapeDataString([string]$AccountId)
  $flavor  = Get-DependentsApiFlavor -PVWAUrl $PVWAUrl

  if ($flavor -eq 'ISPSS') {
    if ($DepId) {
      $depEsc = [uri]::EscapeDataString([string]$DepId)
      return "$baseUrl/api/accounts/$acctEsc/account-dependents/$depEsc"
    }
    return "$baseUrl/api/accounts/$acctEsc/account-dependents"
  }

  # Self-Hosted PAM
  if ($DepId) {
    $depEsc = [uri]::EscapeDataString([string]$DepId)
    return "$baseUrl/PasswordVault/API/Accounts/$acctEsc/dependentAccounts/$depEsc"
  }
  return "$baseUrl/PasswordVault/API/Accounts/$acctEsc/dependentAccounts"
}

function Write-Log { param([string]$Message,[string]$Level="INFO")
  $line = "$(Get-Date -Format s) [$Level] $Message"
  $line | Tee-Object -FilePath $LogPath -Append | Out-Null
}

function Write-ErrorJson {
  param(
    [Parameter(Mandatory)][string]$Method,
    [Parameter(Mandatory)][string]$Uri,
    [int]$StatusCode,
    [string]$Message,
    [string]$ResponseBody,
    [string]$RequestBody
  )
  $obj = [ordered]@{
    time         = (Get-Date -Format s)
    method       = $Method
    uri          = $Uri
    statusCode   = $StatusCode
    message      = $Message
    responseBody = $ResponseBody
    requestBody  = $RequestBody
  }
  ($obj | ConvertTo-Json -Depth 20 -Compress) | Add-Content -Path $ErrorLogPath
}

function As-Array([object]$o) {
  if ($null -eq $o) { return @() }
  if ($o -is [System.Collections.IEnumerable] -and $o -isnot [string]) { return @($o) }
  return ,$o
}

function Get-ArrayFromResponse {
  param([Parameter(Mandatory)][object]$Resp)

  if ($null -eq $Resp) { return @() }

  # If API returned a bare array (including empty []), return it directly
  if ($Resp -is [System.Collections.IEnumerable] -and $Resp -isnot [string]) {
    if ($Resp -is [object[]]) { return @($Resp) }
  }

  $p = $Resp.PSObject.Properties

  # Self-Hosted /dependentAccounts sometimes returns { value: [...] } or a bare array
  if ($p['value'])             { return As-Array $p['value'].Value }

  # ISPSS /account-dependents returns { accountDependents: [...], totalCount: n }
  if ($p['accountDependents']) { return As-Array $p['accountDependents'].Value }

  # Some Self-Hosted variants may wrap in 'dependentAccounts' (rare, but harmless to keep)
  if ($p['dependentAccounts']) { return As-Array $p['dependentAccounts'].Value }

  # Last resort: treat as enumerable if it isn't a string
  if ($Resp -is [System.Collections.IEnumerable] -and $Resp -isnot [string]) {
    return As-Array $Resp
  }

  return @()
}

function Get-Prop {
  param(
    [Parameter(Mandatory)][object]$Object,
    [Parameter(Mandatory)][string[]]$Names
  )
  if ($null -eq $Object) { return $null }

  $psobj = [psobject]$Object

  # 1st pass - direct properties on the object
  foreach ($name in $Names) {
    $prop = $psobj.PSObject.Properties[$name]
    if ($null -ne $prop -and $null -ne $prop.Value) {
      return $prop.Value
    }
  }

  # 2nd pass - platformAccountProperties (for dependentAccounts APIs)
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
  # 3rd pass - platformDependentProperties (for account-dependents endpoint)
  $depProp = $psobj.PSObject.Properties['platformDependentProperties']
  if ($depProp -and $depProp.Value) {
    $plat = $depProp.Value
    if ($plat -is [hashtable]) {
      foreach ($name in $Names) {
        if ($plat.ContainsKey($name) -and $null -ne $plat[$name]) { return $plat[$name] }
      }
    } else {
      $platPs = [psobject]$plat
      foreach ($name in $Names) {
        $inner = $platPs.PSObject.Properties[$name]
        if ($null -ne $inner -and $null -ne $inner.Value) { return $inner.Value }
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
      $status = $null
      $respBody = $null
      $reqBody = $null
      try {
        $resp = $_.Exception.Response
        if ($resp -and $resp.StatusCode) { $status = [int]$resp.StatusCode }
        if ($resp -and $resp.GetResponseStream()) {
          $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
          $respBody = $reader.ReadToEnd()
          $reader.Close()
        }
      } catch {}
      try {
        if ($Body) { $reqBody = ($Body | ConvertTo-Json -Depth 20 -Compress) }
      } catch {}
      Write-ErrorJson -Method $Method -Uri $Uri -StatusCode $status -Message $_.Exception.Message -ResponseBody $respBody -RequestBody $reqBody
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
  $iisPool = Get-Prop $Dep @('AppPool','AppPoolName','ApplicationPool')
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
$IgnoreProps = @('Id','ID','DependencyID','UsageID','AccountId','AccountID','Created','CreationTime','LastModified','LastUpdate','Address','ComputerDnsName','MachineName','Target','HostName','DisplayName','Name','PlatformId','SafeName','LogonDomain')
$IgnoreFlatProps = @('platformDependentProperties.logonDomain','platformAccountProperties.logonDomain')
function Add-FlatProps {
  param(
    [hashtable]$Out,
    [object]$Val,
    [string]$Prefix
  )

  if ($null -eq $Val) { return }

  # Handle hashtable or PSCustomObject
  $pairs = @()

  if ($Val -is [hashtable]) {
    $pairs = $Val.GetEnumerator() | ForEach-Object { @{ Name = $_.Key; Value = $_.Value } }
  } else {
    $pairs = $Val.PSObject.Properties | ForEach-Object { @{ Name = $_.Name; Value = $_.Value } }
  }

  foreach ($p in $pairs) {
    $k = $p.Name
    $v = $p.Value
    if ($null -eq $v) { continue }

    $flatKey = if ($Prefix) { "$Prefix.$k" } else { "$k" }

    if ($IgnoreFlatProps -contains $flatKey) { continue }

    if ($v -is [string] -or $v -is [int] -or $v -is [bool] -or $v -is [double]) {
      $Out[$flatKey] = $v
    } elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
      $Out[$flatKey] = @($v)
    }
    # NOTE: we intentionally do NOT recurse deeper than 1 level
  }
}

function Get-ComparableProps {
  param([hashtable]$Dep)

  $ht = @{}

  foreach ($k in $Dep.Keys) {
    if ($IgnoreProps -contains $k) { continue }
    $val = $Dep[$k]
    if ($null -eq $val) { continue }

    # Flatten the two important nested containers
    if ($k -in @('platformDependentProperties','platformAccountProperties')) {
      Add-FlatProps -Out $ht -Val $val -Prefix $k
      continue
    }

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
	$depFlavor = Get-DependentsApiFlavor -PVWAUrl $PVWAUrl
	$baseUrl = $PVWAUrl.TrimEnd('/')
	if ($Parallel -and $PSVersionTable.PSVersion.Major -lt 7) {
  Write-Log "Parallel requires PowerShell 7+; running sequential." "WARN"
  $Parallel = $false
}
	$Candidates = @()
	$SkipDiscovery = $false
	if ($ResumeFrom) {
  if (-not (Test-Path $ResumeFrom)) { throw "ResumeFrom file not found: $ResumeFrom" }
  $resumeRows = Import-Csv $ResumeFrom
  foreach ($r in $resumeRows) {
    $delta = @{}
    if ($r.DeltaPropsJson -and $r.DeltaPropsJson.Trim() -ne "") {
      $delta = ConvertFrom-Json -InputObject $r.DeltaPropsJson -AsHashtable
    }
    $Candidates += [pscustomobject]@{
      SafeName       = $r.SafeName
      AccountId      = $r.AccountId
      AccountName    = $r.AccountName
      PlatformId     = $r.PlatformId
      Type           = $r.Type
      Machine        = $r.Machine
      ObjectName     = $r.ObjectName
      JoinKey        = $r.JoinKey
      AliasDomain    = $r.AliasDomain
      Authoritative  = $r.Authoritative
      AliasDepId     = $r.AliasDepId
      KeeperDepId    = $r.KeeperDepId
      DeltaProps     = $delta
      AliasRaw       = $null
      KeeperRaw      = $null
    }
  }
  $uniqueAccounts = @($Candidates | Select-Object -Expand AccountId | Sort-Object -Unique)
  Write-Log "ResumeFrom loaded: $ResumeFrom rows=$(@($Candidates).Count) accounts=$($uniqueAccounts.Count)"
  Write-Output "ResumeFrom path: $ResumeFrom"
  Write-Output ("Loaded {0} rows across {1} accounts" -f (@($Candidates).Count), $uniqueAccounts.Count)
  $SkipDiscovery = $true
}

if (-not $SkipDiscovery) {
  # GET all accounts (paged). We'll filter client-side for safety across PVWA versions.
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

    $count = @($batch).Count
    $offset += $PageSize
    Write-Log "Fetched $count accounts" "DEBUG"
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

  # Pull dependencies/usages for each account
  $AllDeps = @()

  if ($Parallel) {
    $depResults = $Accounts | ForEach-Object -Parallel {
      param($acct,$baseUrl,$depFlavor,$headers,$timeoutSec,$accountRetry,$verboseRest)

      function Invoke-LocalRest {
        param(
          [string]$Method,
          [string]$Uri,
          [hashtable]$Headers,
          [object]$Body,
          [int]$TimeoutSec,
          [int]$Retry
        )
        $attempt = 0
        do {
          try {
            if ($Body) {
              return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 50) -TimeoutSec $TimeoutSec
            } else {
              return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec
            }
          } catch {
            $attempt++
            if ($attempt -ge $Retry) { throw }
            Start-Sleep -Seconds ([Math]::Min(2*$attempt,10))
          }
        } while ($true)
      }

      $acctId = $acct.Id
      if (-not $acctId) { return [pscustomobject]@{ Account = $acct; Skip = $true } }
      $acctEsc = [uri]::EscapeDataString([string]$acctId)
      if ($depFlavor -eq 'ISPSS') {
        $depUri = "$baseUrl/api/accounts/$acctEsc/account-dependents"
      } else {
        $depUri = "$baseUrl/PasswordVault/API/Accounts/$acctEsc/dependentAccounts"
      }

      $attempt = 0
      do {
        try {
          $r = Invoke-LocalRest -Method GET -Uri $depUri -Headers $headers -TimeoutSec $timeoutSec -Retry 3
          return [pscustomobject]@{ Account = $acct; DepUri = $depUri; Response = $r }
        } catch {
          $attempt++
          if ($attempt -gt $accountRetry) {
            $status = $null
            $respBody = $null
            try {
              $resp = $_.Exception.Response
              if ($resp -and $resp.StatusCode) { $status = [int]$resp.StatusCode }
              if ($resp -and $resp.GetResponseStream()) {
                $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $respBody = $reader.ReadToEnd()
                $reader.Close()
              }
            } catch {}
            return [pscustomobject]@{
              Account  = $acct
              DepUri   = $depUri
              ErrorInfo = [pscustomobject]@{
                Message      = $_.Exception.Message
                StatusCode   = $status
                ResponseBody = $respBody
              }
            }
          }
          Start-Sleep -Seconds ([Math]::Min(2*$attempt,10))
        }
      } while ($true)
    } -ThrottleLimit $ThrottleLimit

    foreach ($res in $depResults) {
      if ($res.Skip) { continue }
      $acct = $res.Account
      if ($res.ErrorInfo) {
        Write-Log "Dependents endpoint failed for $($acct.Id): $($res.ErrorInfo.Message)" "ERROR"
        Write-ErrorJson -Method "GET" -Uri $res.DepUri -StatusCode $res.ErrorInfo.StatusCode -Message $res.ErrorInfo.Message -ResponseBody $res.ErrorInfo.ResponseBody -RequestBody $null

        $rawWrapperPath = Join-Path $OutDir "raw\acct_$($acct.Id)_wrapper.json"
        (@{ error = $res.ErrorInfo.Message } | ConvertTo-Json -Depth 10) | Out-File -Encoding UTF8 $rawWrapperPath

        $rawArrayPath = Join-Path $OutDir "raw\acct_$($acct.Id)_deps.json"
        "[]" | Out-File -Encoding UTF8 $rawArrayPath
        continue
      }

      $r = $res.Response
      $deps = @( Get-ArrayFromResponse -Resp $r )
      $depCount = $deps.Count

      $rawWrapperPath = Join-Path $OutDir "raw\acct_$($acct.Id)_wrapper.json"
      ($r | ConvertTo-Json -Depth 50) | Out-File -Encoding UTF8 $rawWrapperPath

      $rawArrayPath = Join-Path $OutDir "raw\acct_$($acct.Id)_deps.json"
      ($deps | ConvertTo-Json -Depth 50) | Out-File -Encoding UTF8 $rawArrayPath

      Write-Log ("Dependents response props for {0}: {1}" -f $acct.Id, ((@($r.PSObject.Properties.Name)) -join ',')) "DEBUG"
      Write-Log ("Dependents extracted count for {0}: {1}" -f $acct.Id, $depCount) "DEBUG"

      $rawPath = Join-Path $OutDir "raw\acct_$($acct.Id).json"
      ($deps | ConvertTo-Json -Depth 50) | Out-File -Encoding UTF8 $rawPath

      foreach ($d in $deps) {
        $h = @{}
        foreach ($p in $d.PSObject.Properties.Name) { $h[$p] = $d.$p }

        $domain = Get-Prop $d @('LogonDomain','Domain','AccountDomain')
        $user   = Get-Prop $d @('LogonUser','LogonUserName','User','UserName','AccountName')
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
  } else {
    foreach ($acct in $Accounts) {
      if (-not $acct.Id) { continue }

      $depUri = Get-AccountDependentsUri -PVWAUrl $PVWAUrl -AccountId $acct.Id

      $attempt = 0
      $lastErr = $null
      $r = $null
      $depOk = $false
      do {
        try {
          $r = Invoke-PVWARest -Method GET -Uri $depUri -Headers $Headers
          $depOk = $true
          break
        } catch {
          $lastErr = $_
          $attempt++
          if ($attempt -gt $AccountRetry) { break }
          Write-Log "Dependents endpoint retry for $($acct.Id) (attempt $attempt)" "WARN"
          Start-Sleep -Seconds ([Math]::Min(2*$attempt,10))
        }
      } while ($true)

      if (-not $depOk) {
        $errMsg = if ($lastErr) { $lastErr.Exception.Message } else { "Unknown error" }
        Write-Log "Dependents endpoint failed for $($acct.Id): $errMsg" "ERROR"

        $rawWrapperPath = Join-Path $OutDir "raw\acct_$($acct.Id)_wrapper.json"
        (@{ error = $errMsg } | ConvertTo-Json -Depth 10) | Out-File -Encoding UTF8 $rawWrapperPath

        $rawArrayPath = Join-Path $OutDir "raw\acct_$($acct.Id)_deps.json"
        "[]" | Out-File -Encoding UTF8 $rawArrayPath
        continue
      }

      # Always normalize to an array (never $null)
      $deps = @( Get-ArrayFromResponse -Resp $r )   # forces array context
      $depCount = $deps.Count                       # fail safe

      # Write wrapper and extracted array AFTER extraction
      $rawWrapperPath = Join-Path $OutDir "raw\acct_$($acct.Id)_wrapper.json"
      ($r | ConvertTo-Json -Depth 50) | Out-File -Encoding UTF8 $rawWrapperPath

      $rawArrayPath = Join-Path $OutDir "raw\acct_$($acct.Id)_deps.json"
      ($deps | ConvertTo-Json -Depth 50) | Out-File -Encoding UTF8 $rawArrayPath

      Write-Log ("Dependents response props for {0}: {1}" -f $acct.Id, ((@($r.PSObject.Properties.Name)) -join ',')) "DEBUG"
      Write-Log ("Dependents extracted count for {0}: {1}" -f $acct.Id, $depCount) "DEBUG"

      # Save raw snapshot (keep your existing naming if you want)
      $rawPath = Join-Path $OutDir "raw\acct_$($acct.Id).json"
      ($deps | ConvertTo-Json -Depth 50) | Out-File -Encoding UTF8 $rawPath

      foreach ($d in $deps) {
        $h = @{}
        foreach ($p in $d.PSObject.Properties.Name) { $h[$p] = $d.$p }

        $domain = Get-Prop $d @('LogonDomain','Domain','AccountDomain')
        $user   = Get-Prop $d @('LogonUser','LogonUserName','User','UserName','AccountName')  # expanded a bit

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
  }

  Write-Log "Dependencies/usages collected: $($AllDeps.Count)"

  # Identify duplicates: same Account + JoinKey but different domain strings (alias vs authoritative)
  $groups = $AllDeps | Group-Object -Property AccountId, JoinKey
  $Candidates = @()
  foreach ($g in $groups) {
    $items = $g.Group
    if (@($items).Count -lt 2) { continue }
    # Partition by whether domain is alias
    $alias = @($items | Where-Object { $_.DomainOriginal -and $AliasSet.Contains($_.DomainOriginal) })
    if (@($alias).Count -eq 0) { continue }

    $auth  = @($items | Where-Object { $_.DomainMapped -and ($_.DomainMapped -eq $_.DomainOriginal) })
    if (@($auth).Count -eq 0) { continue }

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
  $uniqueAccounts = @($Candidates | Select-Object -Expand AccountId | Sort-Object -Unique)
  Write-Output ("Found {0} alias duplicates across {1} accounts" -f (@($Candidates).Count), $uniqueAccounts.Count)
}
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

  $u = Get-AccountDependentsUri -PVWAUrl $PVWAUrl -AccountId $AccountId -DepId $DepId

  $flavor = Get-DependentsApiFlavor -PVWAUrl $PVWAUrl
  if ($flavor -eq 'ISPSS') {
    # ISPSS /account-dependents rejects PATCH and partial PUT for updates.
    try {
      $current = Invoke-PVWARest -Method GET -Uri $u -Headers $Headers
      $full = Convert-DependentToPayload -Dep $current -NewProps $NewProps
      $null = Invoke-PVWARest -Method PUT -Uri $u -Headers $Headers -Body $full
      Write-Log "Merged props into keeper via PUT(full) dependents endpoint: acct=$AccountId dep=$DepId keys=[$(($full.Keys -join ','))]"
      return $true
    } catch {
      Write-Log "PUT(full) dependents endpoint failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "ERROR"
      return $false
    }
  }

  $lastErr = $null
  foreach ($method in @('PATCH','PUT')) {
    try {
      $null = Invoke-PVWARest -Method $method -Uri $u -Headers $Headers -Body $payload
      Write-Log "Merged props into keeper via $method dependents endpoint: acct=$AccountId dep=$DepId keys=[$(($payload.Keys -join ','))]"
      return $true
    } catch {
      $lastErr = $_
      Write-Log "$method dependents endpoint failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "WARN"
    }
  }

  # Fallback: PUT a full object (some ISPSS endpoints reject partial payloads)
  try {
    $current = Invoke-PVWARest -Method GET -Uri $u -Headers $Headers
  } catch {
    Write-Log "GET dependents endpoint failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "ERROR"
    return $false
  }

  $full = Convert-DependentToPayload -Dep $current -NewProps $NewProps
  try {
    $null = Invoke-PVWARest -Method PUT -Uri $u -Headers $Headers -Body $full
    Write-Log "Merged props into keeper via PUT(full) dependents endpoint: acct=$AccountId dep=$DepId keys=[$(($full.Keys -join ','))]"
    return $true
  } catch {
    $lastErr = $_
    Write-Log "PUT(full) dependents endpoint failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "ERROR"
  }

  Write-Log "All merge attempts failed for acct=$AccountId dep=${DepId}: $($lastErr.Exception.Message)" "ERROR"
  return $false
}

function Delete-Dependency {
  param(
    [Parameter(Mandatory)][string]$AccountId,
    [Parameter(Mandatory)][string]$DepId,
    [Parameter(Mandatory)][hashtable]$AliasRaw
  )

  if ($null -eq $AliasRaw -or $AliasRaw.Keys.Count -eq 0) {
    try {
      $AliasRaw = Get-DependentHashtable -AccountId $AccountId -DepId $DepId
    } catch {
      Write-Log "Fetch alias raw failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "WARN"
      $AliasRaw = @{}
    }
  }
  if ($AliasRaw.Keys.Count -gt 0) {
    # archive alias JSON first
    $stamp = Get-Date -Format "yyyyMMdd_HHmmssfff"
    $arch = Join-Path $OutDir ("archive\alias_acct{0}_dep{1}_{2}.json" -f $AccountId,$DepId,$stamp)
    ($AliasRaw | ConvertTo-Json -Depth 50) | Out-File -Encoding UTF8 $arch
  }

  $u = Get-AccountDependentsUri -PVWAUrl $PVWAUrl -AccountId $AccountId -DepId $DepId

  try {
    $null = Invoke-PVWARest -Method DELETE -Uri $u -Headers $Headers
    Write-Log "Deleted alias via DELETE dependents endpoint: acct=$AccountId dep=$DepId"
    return $true
  } catch {
    Write-Log "DELETE dependents endpoint failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "ERROR"
    return $false
  }
}

function Convert-DeltaToPayload {
  param([hashtable]$Delta)

  $payload = @{}
  foreach ($k in $Delta.Keys) {
    $v = $Delta[$k]

    if ($k -like 'platformDependentProperties.*') {
      if (-not $payload.ContainsKey('platformDependentProperties')) { $payload['platformDependentProperties'] = @{} }
      $inner = $k.Substring('platformDependentProperties.'.Length)
      $payload['platformDependentProperties'][$inner] = $v
    }
    elseif ($k -like 'platformAccountProperties.*') {
      if (-not $payload.ContainsKey('platformAccountProperties')) { $payload['platformAccountProperties'] = @{} }
      $inner = $k.Substring('platformAccountProperties.'.Length)
      $payload['platformAccountProperties'][$inner] = $v
    }
    else {
      $payload[$k] = $v
    }
  }

  return $payload
}

function Filter-DeltaByKeys {
  param(
    [Parameter(Mandatory)][hashtable]$Delta,
    [string[]]$OnlyKeys
  )
  if (-not $OnlyKeys -or $OnlyKeys.Count -eq 0) { return $Delta }

  $filtered = @{}
  foreach ($k in $Delta.Keys) {
    foreach ($pat in $OnlyKeys) {
      if ($k -like $pat) { $filtered[$k] = $Delta[$k]; break }
    }
  }
  return $filtered
}

function Get-DepHashtable {
  param([Parameter(Mandatory)][object]$Dep)
  $h = @{}
  foreach ($p in $Dep.PSObject.Properties.Name) { $h[$p] = $Dep.$p }
  return $h
}

function Verify-DependencyProps {
  param(
    [Parameter(Mandatory)][string]$AccountId,
    [Parameter(Mandatory)][string]$DepId,
    [Parameter(Mandatory)][hashtable]$ExpectedDelta
  )

  if ($ExpectedDelta.Keys.Count -eq 0) { return $true }

  $u = Get-AccountDependentsUri -PVWAUrl $PVWAUrl -AccountId $AccountId -DepId $DepId
  try {
    $dep = Invoke-PVWARest -Method GET -Uri $u -Headers $Headers
  } catch {
    Write-Log "Post-merge verify GET failed for acct=$AccountId dep=${DepId}: $($_.Exception.Message)" "ERROR"
    return $false
  }

  $ht = Get-DepHashtable -Dep $dep
  $current = Get-ComparableProps -Dep $ht

  foreach ($k in $ExpectedDelta.Keys) {
    if (-not $current.ContainsKey($k)) { return $false }
    $a = $ExpectedDelta[$k]; $b = $current[$k]
    if ($a -is [System.Collections.IEnumerable] -and $a -isnot [string]) {
      if ((@($a) -join '|') -ne (@($b) -join '|')) { return $false }
    } else {
      if ("$a" -ne "$b") { return $false }
    }
  }
  return $true
}

function Get-DependentHashtable {
  param(
    [Parameter(Mandatory)][string]$AccountId,
    [Parameter(Mandatory)][string]$DepId
  )
  $u = Get-AccountDependentsUri -PVWAUrl $PVWAUrl -AccountId $AccountId -DepId $DepId
  $dep = Invoke-PVWARest -Method GET -Uri $u -Headers $Headers
  return Get-DepHashtable -Dep $dep
}

function Convert-DependentToPayload {
  param(
    [Parameter(Mandatory)][object]$Dep,
    [Parameter(Mandatory)][hashtable]$NewProps
  )

  $skip = @('createdAt','modifiedAt','safeId')
  $payload = @{}

  foreach ($p in $Dep.PSObject.Properties) {
    if ($skip -contains $p.Name) { continue }
    $payload[$p.Name] = $p.Value
  }

  foreach ($k in $NewProps.Keys) {
    $v = $NewProps[$k]
    if ($k -in @('platformDependentProperties','platformAccountProperties') -and $v -is [hashtable]) {
      if (-not $payload.ContainsKey($k) -or $null -eq $payload[$k]) { $payload[$k] = @{} }
      $target = @{}
      if ($payload[$k] -is [hashtable]) {
        foreach ($tk in $payload[$k].Keys) { $target[$tk] = $payload[$k][$tk] }
      } else {
        foreach ($tp in $payload[$k].PSObject.Properties) { $target[$tp.Name] = $tp.Value }
      }
      foreach ($vk in $v.Keys) { $target[$vk] = $v[$vk] }
      $payload[$k] = $target
      continue
    }
    $payload[$k] = $v
  }

  return $payload
}

	# Execute plan
  $success = 0
$merged  = 0
$deleted = 0
$AccountSummary = @{}
	foreach ($row in $Candidates) {
  $acctId   = $row.AccountId
  $aliasDep = $row.AliasDepId
  $keepDep  = $row.KeeperDepId
  if (-not $AccountSummary.ContainsKey($acctId)) {
    $AccountSummary[$acctId] = [ordered]@{
      AccountId            = $acctId
      MergeAttempted       = 0
      MergeOk              = 0
      MergeFailed          = 0
      MergeSkippedCap      = 0
      MergeSkippedFilter   = 0
      MergeVerifyOk        = 0
      MergeVerifyFailed    = 0
      DeleteOk             = 0
      DeleteSkippedCap     = 0
      DeleteSkippedMerge   = 0
    }
  }
	# Merge keeper with alias delta
  $delta = $row.DeltaProps
  $mergedOk = $true
  if ($delta -and $delta.Keys.Count -gt 0) {
    $delta = Filter-DeltaByKeys -Delta $delta -OnlyKeys $OnlyMergeKeys
    if (-not $delta -or $delta.Keys.Count -eq 0) {
      Write-Log "Skipping merge due to OnlyMergeKeys filter: acct=$acctId keeperDep=$keepDep" "DEBUG"
      $AccountSummary[$acctId].MergeSkippedFilter++
      $mergedOk = $true
    } elseif ($MaxMerges -gt 0 -and $merged -ge $MaxMerges) {
      Write-Log "Skipping merge due to MaxMerges cap: acct=$acctId keeperDep=$keepDep" "WARN"
      $AccountSummary[$acctId].MergeSkippedCap++
      $mergedOk = $false
    } else {
      $AccountSummary[$acctId].MergeAttempted++
      $payload = Convert-DeltaToPayload -Delta $delta
      $mergedOk = Update-Dependency -AccountId $acctId -DepId $keepDep -NewProps $payload
      if ($mergedOk) {
        $merged++
        $AccountSummary[$acctId].MergeOk++
        $verifyOk = Verify-DependencyProps -AccountId $acctId -DepId $keepDep -ExpectedDelta $delta
        if ($verifyOk) {
          $AccountSummary[$acctId].MergeVerifyOk++
        } else {
          $AccountSummary[$acctId].MergeVerifyFailed++
          Write-Log "Post-merge verify failed: acct=$acctId keeperDep=$keepDep keys=[$(($delta.Keys -join ','))]" "WARN"
        }
      } else {
        $AccountSummary[$acctId].MergeFailed++
      }
    }
  }
  if (-not $mergedOk) {
    Write-Log "Skipping delete because merge failed: acct=$acctId aliasDep=$aliasDep keeperDep=$keepDep" "WARN"
    $AccountSummary[$acctId].DeleteSkippedMerge++
    continue
  }
	# Delete alias duplicate
  if ($MaxDeletes -gt 0 -and $deleted -ge $MaxDeletes) {
    Write-Log "Skipping delete due to MaxDeletes cap: acct=$acctId aliasDep=$aliasDep" "WARN"
    $AccountSummary[$acctId].DeleteSkippedCap++
    continue
  }
  $delOk = Delete-Dependency -AccountId $acctId -DepId $aliasDep -AliasRaw $row.AliasRaw
  if ($delOk) {
    $deleted++
    $AccountSummary[$acctId].DeleteOk++
  }
	if ($mergedOk -and $delOk) { $success++ }
}
	Write-Log "Merge attempts: $merged, Deletes: $deleted, Success pairs: $success"
	if ($AccountSummary.Count -gt 0) {
  $summaryList = $AccountSummary.Values | ForEach-Object {
    [pscustomobject]@{
      AccountId        = $_.AccountId
      MergeAttempted   = $_.MergeAttempted
      MergeOk          = $_.MergeOk
      MergeFailed      = $_.MergeFailed
      MergeSkippedCap  = $_.MergeSkippedCap
      MergeSkippedFilter = $_.MergeSkippedFilter
      MergeVerifyOk    = $_.MergeVerifyOk
      MergeVerifyFailed = $_.MergeVerifyFailed
      DeleteOk         = $_.DeleteOk
      DeleteSkippedCap = $_.DeleteSkippedCap
      DeleteSkippedMerge = $_.DeleteSkippedMerge
    }
  }
  $SummaryPath = Join-Path $OutDir "summary.csv"
  $summaryList | Export-Csv -NoTypeInformation -Encoding UTF8 $SummaryPath
  Write-Output "Summary: $SummaryPath"
  $summaryList | Sort-Object AccountId | Format-Table -AutoSize | Out-String | Write-Output
}
	# Post-state verify for touched accounts
$Touched = $Candidates | Select-Object -Expand AccountId -Unique
$Post = @()
foreach ($acctId in $Touched) {
  $depUri = Get-AccountDependentsUri -PVWAUrl $PVWAUrl -AccountId $acctId
  $deps = @()

  try {
    $r = Invoke-PVWARest -Method GET -Uri $depUri -Headers $Headers
    $deps = @( Get-ArrayFromResponse -Resp $r )
  } catch {
    Write-Log "Post-verify failed for acct=${acctId}: $($_.Exception.Message)" "ERROR"
    continue
  }

  foreach ($d in $deps) {
    $h = @{}
    foreach ($p in $d.PSObject.Properties.Name) { $h[$p] = $d.$p }

    $domain = Get-Prop $d @('LogonDomain','Domain','AccountDomain')
    $user   = Get-Prop $d @('LogonUser','User','UserName','AccountName')
    $canon  = Get-CanonicalIdentifiers -Dep $d

    $Post += [pscustomobject]@{
      AccountId    = $acctId
      DepId        = $h['Id'] ?? $h['ID'] ?? $h['DependencyID'] ?? $h['UsageID'] ?? $h['dependentAccountId']
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


