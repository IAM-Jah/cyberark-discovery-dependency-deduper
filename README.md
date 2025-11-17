# CyberArk Discovery Dependency Deduper

PowerShell tool for cleaning up **alias-domain discovery dependencies and usages** in CyberArk PAM.

The script looks for account dependencies/usages discovered against an **alias domain** (for example `domain.edu` or a NETBIOS name) that are duplicates of entries using an **authoritative domain** (for example `subdomain.domain.edu`). It builds a dry-run plan and, when confirmed, merges useful settings into the authoritative dependency and deletes the alias duplicate via the REST APIs.

It supports both:

- **CyberArk Privilege Cloud on Identity Security Platform Shared Services (ISPSS)**
- **CyberArk PAM Self-Hosted (EPV/PVWA)**

---

## Features

- Identifies duplicate discovery dependencies/usages based on an alias → authoritative domain mapping.
- Generates a **dry-run CSV plan** describing all proposed merges and deletions.
- Optionally merges selected properties from alias dependencies into their authoritative counterparts and deletes aliases.
- Writes **raw** and **archived** JSON snapshots for audit, rollback and troubleshooting.
- Supports **bearer token** authentication (Privilege Cloud / ISPSS, or Self-Hosted integrated with Identity) and **classic PVWA logon** (Self-Hosted).

---

## Supported environments

- **Privilege Cloud on ISPSS**

  - Use an Identity/ISPSS bearer token.
  - Use the Privilege Cloud tenant URL as `PVWAUrl`, e.g.  
    `https://<subdomain>.privilegecloud.cyberark.cloud`

- **PAM Self-Hosted (EPV/PVWA)**

  - Use either:
    - A CyberArk/LDAP/RADIUS credential with `-Credential` and `-AuthType`, or
    - A bearer token if your PVWA is integrated with Identity/ISPSS and exposes the same APIs.
  - Use the PVWA base URL as `PVWAUrl`, e.g.  
    `https://pvwa.company.com`

> **Important:** In all cases, do **not** append `/PasswordVault` to `PVWAUrl`.  
> The script adds `/PasswordVault/API/...` internally.

---

## Requirements

- PowerShell 5.1+ or PowerShell 7+.
- Network connectivity from the host running the script to:
  - Privilege Cloud PVWA, or
  - Self-Hosted PVWA.
- A user or service identity with permissions to:
  - Query accounts and their dependencies/usages.
  - Modify and delete dependencies/usages.
- An alias → authoritative domain mapping that reflects how you want discovery data normalized.

---

## Script parameters

The script is defined as:

```powershell
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory = $true)][string]   $PVWAUrl,
  [Parameter()][pscredential]              $Credential,
  [Parameter()][string]                    $AuthType = "CyberArk",
  [Parameter()][string]                    $BearerToken,
  [Parameter()][string]                    $AliasMapPath,
  [Parameter()][hashtable]                 $AliasMap,
  [Parameter()][string[]]                  $SafeFilter,
  [Parameter()][string[]]                  $PlatformIdFilter,
  [Parameter()][string[]]                  $AccountNameFilter,
  [Parameter()][string]                    $OutDir = ".\out",
  [Parameter()][switch]                    $Apply,
  [Parameter()][switch]                    $Force,
  [Parameter()][int]                       $PageSize = 100,
  [Parameter()][int]                       $TimeoutSec = 60,
  [Parameter()][switch]                    $VerboseRest,
  [Parameter()][switch]                    $SkipCertValidation
)
```

### Key parameters

- **`PVWAUrl`** (mandatory)  
  Base URL for PVWA/Privilege Cloud (without `/PasswordVault`).

  - Privilege Cloud: `https://<subdomain>.privilegecloud.cyberark.cloud`
  - Self-Hosted: `https://pvwa.company.com`

- **`BearerToken`** (token-based auth; recommended for Privilege Cloud)  
  Pre-acquired OAuth/JWT token for Privilege Cloud/EPV. The script sends:

  ```http
  Authorization: Bearer <BearerToken>
  ```

- **`Credential`** and **`AuthType`** (classic PVWA logon; Self-Hosted)  
  When `-BearerToken` is not specified, the script will:

  - Use `-Credential` (CyberArk/LDAP/RADIUS user with EPV permissions).
  - Call the appropriate PVWA logon endpoint, for example:  
    `https://pvwa.company.com/PasswordVault/API/Auth/CyberArk/Logon`

  Leave `AuthType` as `CyberArk` for native Vault users, or set values such as `LDAP` according to your configuration.

- **`AliasMapPath`** / **`AliasMap`**  
  Mapping from alias domains to authoritative domains.

  *JSON file (for `-AliasMapPath`):*

  ```json
  {
    "domain.edu": "subdomain.domain.edu",
    "NETBIOS":    "subdomain.domain.edu"
  }
  ```

  *Inline hashtable (for `-AliasMap`):*

  ```powershell
  @{
    "domain.edu" = "subdomain.domain.edu"
    "NETBIOS"    = "subdomain.domain.edu"
  }
  ```

- **Filters** (strongly recommended for early runs)

  - `SafeFilter` – one or more Safe names to include.
  - `PlatformIdFilter` – one or more platform IDs (for example `WinDomain`, `WinServerLocal`, `UnixSSH`).
  - `AccountNameFilter` – wildcard patterns to narrow by account name (system, user, or other identifying field).

- **Execution / safety**

  - `OutDir` – folder for logs, CSVs and JSON (default: `.\out`).
  - `Apply` – when set, performs merges and deletions; when omitted, the run is **dry-run only**.
  - `Force` – when used with `-Apply`, skips the interactive "Type YES to continue" confirmation.
  - `VerboseRest` – logs REST calls in detail.
  - `SkipCertValidation` – disables TLS validation (for lab-only scenarios).

---

## Authentication options

### Option A – Bearer token (`-BearerToken`)

Use this for:

- **Privilege Cloud on ISPSS** (Identity/ISPSS token).
- **Self-Hosted** integrated with Identity/ISPSS when you have an appropriate platform token.

Typical IdentityAuth.psm1 pattern:

```powershell
Import-Module "C:\Path\To\IdentityAuth.psm1"

$IdentityTenantURL = "https://<tenant-id>.id.cyberark.cloud"
$svcCred           = Get-Credential      # or provided by your automation

# Often returns a string like "Bearer eyJ..." or a hashtable with Authorization
$header = Get-IdentityHeader -IdentityTenantURL $IdentityTenantURL -UPCreds $svcCred
```

The script expects **just the token**, not the `"Bearer "` prefix.

If `$header` is a **string**:

```powershell
$token = ($header -split '\s+', 2)[1]
```

If `$header` is a **hashtable** with an `Authorization` key:

```powershell
$token = ($header.Authorization -split '\s+', 2)[1]
```

Use `$token` with `-BearerToken` in the examples below.

### Option B – Classic PVWA logon (`-Credential` / `-AuthType`, Self-Hosted)

For **Self-Hosted** EPV/PVWA you can also allow the script to log on for you:

```powershell
$PVWAUrl = "https://pvwa.company.com"
$cred    = Get-Credential     # PVWA user with the required rights

.\DeleteDuplicateDependencies.ps1 `
  -PVWAUrl    $PVWAUrl `
  -Credential $cred `
  -AuthType   "CyberArk" `
  -AliasMap   @{
      "domain.edu" = "subdomain.domain.edu"
      "NETBIOS"    = "subdomain.domain.edu"
  } `
  -SafeFilter "SomeSafe"
```

The script will call the appropriate `/Auth/.../Logon` endpoint, obtain a logon token and use it for subsequent API calls.

---

## Usage: Privilege Cloud on ISPSS

### Dry-run (test mode)

Dry-run mode **never modifies** anything in Privilege Cloud. It:

- Calls the Accounts/Dependencies/Usages APIs.
- Applies your alias map.
- Writes a `dry-run.csv` describing the changes it *would* make.
- Writes raw JSON snapshots to disk for review.

```powershell
$PVWAUrl = "https://<subdomain>.privilegecloud.cyberark.cloud"
$OutDir  = ".\dep-dedupe-pcloud-test"

# Assume $token is already set (raw JWT, no "Bearer ")
.\DeleteDuplicateDependencies.ps1 `
  -PVWAUrl    $PVWAUrl `
  -BearerToken $token `
  -AliasMap   @{
      "domain.edu" = "subdomain.domain.edu"
      "NETBIOS"    = "subdomain.domain.edu"
  } `
  -SafeFilter "SomeTestSafe" `
  -OutDir    $OutDir
```

This will create in `$OutDir`:

- `actions.log` – log of the run.
- `raw\acct_<AccountId>.json` – raw dependencies/usages as returned by the API.
- `dry-run.csv` – the plan showing alias vs authoritative entries, IDs and deltas.

The script will print output similar to:

```text
Dry-run path: .\dep-dedupe-pcloud-test\dry-run.csv
Found <N> alias duplicates across <M> accounts
Analysis complete. Re-run with -Apply (and optionally -Force) to perform merges/deletes.
```

Review `dry-run.csv` in Excel/Power BI and confirm:

- Alias domains are correct.
- Authoritative entries are correctly identified.
- The proposed field changes look correct.

### Write run (perform merges and deletes)

Once you’re satisfied with the dry-run output:

```powershell
$PVWAUrl = "https://<subdomain>.privilegecloud.cyberark.cloud"
$OutDir  = ".\dep-dedupe-pcloud-prod"

.\DeleteDuplicateDependencies.ps1 `
  -PVWAUrl     $PVWAUrl `
  -BearerToken $token `
  -AliasMapPath ".\alias-map.json" `
  -OutDir      $OutDir `
  -Apply
```

Behavior:

1. Recomputes candidates and rewrites `dry-run.csv`.
2. Shows a summary and asks you to type `YES` to continue:

   ```text
   Dry-run path: .\dep-dedupe-pcloud-prod\dry-run.csv
   Found <N> alias duplicates across <M> accounts
   About to MERGE and DELETE N alias dependencies. Type 'YES' to continue
   ```

3. If you type `YES` (in all caps), it will:
   - Archive alias dependencies as JSON in `archive\...`.
   - Merge relevant fields into the authoritative dependency.
   - Delete alias dependencies.
   - Log each operation to `actions.log`.

4. At the end it reads back the updated state and writes a `post-state.csv`, then prints something like:

   ```text
   Done. Merged: <X>; Deleted: <Y>; Success pairs: <Z>
   Post-state: .\dep-dedupe-pcloud-prod\post-state.csv
   ```

For non-interactive use (for example, a scheduled job), add `-Force` to skip the confirmation prompt:

```powershell
.\DeleteDuplicateDependencies.ps1 `
  -PVWAUrl      $PVWAUrl `
  -BearerToken  $token `
  -AliasMapPath ".\alias-map.json" `
  -OutDir       $OutDir `
  -Apply `
  -Force
```

---

## Usage: PAM Self-Hosted (EPV/PVWA)

You can run the script against Self-Hosted PVWA using either `-BearerToken` (if you have Identity/ISPSS tokens configured) or the classic `-Credential` / `-AuthType` pattern.

### Self-Hosted dry-run via classic PVWA logon

```powershell
$PVWAUrl = "https://pvwa.company.com"
$OutDir  = ".\dep-dedupe-epv-test"
$cred    = Get-Credential   # EPV user with appropriate rights

.\DeleteDuplicateDependencies.ps1 `
  -PVWAUrl    $PVWAUrl `
  -Credential $cred `
  -AuthType   "CyberArk" `
  -AliasMap   @{
      "domain.edu" = "subdomain.domain.edu"
      "NETBIOS"    = "subdomain.domain.edu"
  } `
  -SafeFilter "SomeSafe" `
  -PlatformIdFilter "WinDomain","WinServerLocal" `
  -OutDir    $OutDir
```

This behaves like the Privilege Cloud dry-run:

- No changes are made to the Vault.
- `actions.log`, `raw\*.json` and `dry-run.csv` are written to `$OutDir`.
- The console shows how many duplicates were found and where the CSV is located.

### Self-Hosted write run via classic PVWA logon

```powershell
$PVWAUrl = "https://pvwa.company.com"
$OutDir  = ".\dep-dedupe-epv-prod"
$cred    = Get-Credential

.\DeleteDuplicateDependencies.ps1 `
  -PVWAUrl      $PVWAUrl `
  -Credential   $cred `
  -AuthType     "CyberArk" `
  -AliasMapPath ".\alias-map.json" `
  -OutDir       $OutDir `
  -Apply
```

The flow mirrors the Privilege Cloud write run:

1. Recomputes and writes `dry-run.csv`.
2. Prompts for `YES`.
3. Archives alias dependencies, merges into authoritative ones and deletes aliases.
4. Writes `post-state.csv` and a summary line at the end.

As with Privilege Cloud, you can add `-Force` for non-interactive automation **after** you have thoroughly tested the behavior in your environment.

---

## Output files and directories

For each run, the script writes to `OutDir`:

- **`actions.log`**  
  Timestamped log of operations, warnings and errors.

- **`dry-run.csv`**  
  Plan of alias vs authoritative dependencies, including:
  - Safe / account identifiers.
  - Alias vs keeper IDs.
  - Domains, machines, object names.
  - A JSON column with the proposed property deltas.

- **`post-state.csv`** (write runs only)  
  Snapshot of the dependencies/usages after merges and deletes.

- **`raw\`**  
  Raw account/dependency JSON snapshots exactly as returned by the API.

- **`archive\`** (write runs only)  
  Archived copies of alias dependencies before deletion, suitable for rollback or audit.

---

## Recommended workflow

1. **Define your alias map**  
   Decide which domains/hostnames are considered alias vs authoritative and store them in `alias-map.json` (or an inline hashtable).

2. **Run a scoped dry run**  
   Target a small set of Safes/platforms and confirm that `dry-run.csv` reflects the duplicates you expect.

3. **Expand dry-run coverage**  
   Increase the number of Safes/platforms and revalidate the results.

4. **Perform a carefully scoped write run**  
   Use `-Apply` (and confirm with `YES`) in a controlled scope. Review `post-state.csv` and `archive\` outputs.

5. **Automate if desired**  
   Once comfortable with the results, consider scheduled executions with `-Apply -Force` and appropriate monitoring/alerting.

Use the archived JSON and CSV outputs as your audit trail for change control and troubleshooting in both Privilege Cloud and Self-Hosted deployments.
