# CyberArk Discovery Dependency Deduper

Deduplicates alias-domain discovery dependencies/usages in CyberArk Privilege Cloud and Self-Hosted PAM.
It identifies dependencies discovered against an alias domain (for example, `corp`) that duplicate authoritative ones
(for example, `corp.example.com`), merges selected settings into the authoritative dependent, and deletes the alias.

The script is safe by default: it produces a dry-run plan and only applies changes when `-Apply` is specified.

## Features

- Supports ISPSS `/api/accounts/{id}/account-dependents` and Self-Hosted `/PasswordVault/API/Accounts/{id}/dependentAccounts`.
- Detects alias duplicates using a domain map.
- Diff-based merge with nested platform properties (for example, `restartService`).
- Prevents `logonDomain` from being merged back into authoritative entries.
- Safe merge logic for Privilege Cloud: GET + PUT(full) for dependents updates.
- Detailed logging plus JSON error log (`errors.jsonl`).
- Merge/delete safety caps and optional merge key filters.
- Optional parallel dependents fetch (PowerShell 7+).
- Resume from a prior dry-run CSV.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+ (parallel fetch requires PowerShell 7+).
- Network access to PVWA.
- Permissions to read accounts and update/delete dependents.

## Quick Start

```powershell
# Dry run
.\cyberark-discovery-dependency-deduper.ps1 `
  -PVWAUrl https://subdomain.privilegecloud.cyberark.cloud `
  -BearerToken <token> `
  -AliasMap @{ 'corp' = 'corp.example.com' }

# Apply changes with a safety cap
.\cyberark-discovery-dependency-deduper.ps1 `
  -PVWAUrl https://subdomain.privilegecloud.cyberark.cloud `
  -BearerToken <token> `
  -AliasMap @{ 'corp' = 'corp.example.com' } `
  -Apply -MaxMerges 10 -MaxDeletes 10
```

## Parameters

- `-PVWAUrl` (required): PVWA base URL.
- `-Credential`: PSCredential for classic PVWA logon (ignored if `-BearerToken` is provided).
- `-AuthType`: Classic logon auth type (default: `CyberArk`).
- `-BearerToken`: Pre-acquired OAuth/JWT token.
- `-AliasMapPath`: Path to JSON file with alias -> authoritative mappings.
- `-AliasMap`: Hashtable of alias -> authoritative mappings.
- `-SafeFilter`: One or more Safe names to include.
- `-PlatformIdFilter`: One or more platform IDs to include.
- `-AccountNameFilter`: Wildcards to include accounts (server/username).
- `-OutDir`: Output folder (default: `.\out\YYYYMMDD_HHMMSS`).
- `-Apply`: Perform merges/deletes (otherwise dry run).
- `-PlanOnly`: Always run in dry-run mode, even if `-Apply` is set.
- `-Force`: Skip confirmation prompt when `-Apply`.
- `-OnlyMergeKeys`: Limit which delta keys can be merged (supports wildcards).
- `-MaxMerges`: Cap merge operations (0 = unlimited).
- `-MaxDeletes`: Cap delete operations (0 = unlimited).
- `-ResumeFrom`: Path to a prior `dry-run.csv` to replay only those rows.
- `-Parallel`: Fetch dependents in parallel (PowerShell 7+ only).
- `-ThrottleLimit`: Parallel task limit (default: 4).
- `-AccountRetry`: Extra per-account GET retries (in addition to per-call retries).
- `-VerboseRest`: Log REST calls at DEBUG level.
- `-SkipCertValidation`: Disable certificate validation.

## Output Files

Each run writes to `OutDir`:

- `dry-run.csv`: Proposed merges and deletes (always).
- `actions.log`: Human-readable log of actions.
- `errors.jsonl`: One JSON object per REST failure (request/response details).
- `summary.csv`: Per-account merge/delete summary (when `-Apply`).
- `post-state.csv`: Post-merge snapshot for touched accounts (when `-Apply`).
- `raw/`: Raw dependents API snapshots.
- `archive/`: Archived alias dependents (JSON) before delete.

## Resume a Prior Plan

```powershell
.\cyberark-discovery-dependency-deduper.ps1 `
  -PVWAUrl https://subdomain.privilegecloud.cyberark.cloud `
  -BearerToken <token> `
  -ResumeFrom .\out\20260110_120004\dry-run.csv `
  -Apply
```

## Limit What Gets Merged

Only merge a specific property:

```powershell
.\cyberark-discovery-dependency-deduper.ps1 `
  -PVWAUrl https://subdomain.privilegecloud.cyberark.cloud `
  -BearerToken <token> `
  -AliasMap @{ 'corp' = 'corp.example.com' } `
  -OnlyMergeKeys platformDependentProperties.restartService `
  -Apply
```

## Notes

- The script intentionally ignores `logonDomain` during merges so authoritative logon values are preserved.
- For Privilege Cloud, the script updates dependents via GET + PUT(full) to satisfy the endpoint.
- Always review `dry-run.csv` before running with `-Apply`.

## License

MIT License
