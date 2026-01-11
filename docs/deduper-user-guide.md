# CyberArk Discovery Dependency Deduper  
Client User Guide

## Overview

In CyberArk Privilege Cloud and PAM Self-Hosted environments, account discovery can create duplicate dependent accounts (also referred to as dependencies or usages) when the same credential is discovered using different domain representations. Common examples include short NetBIOS domains, legacy domains, local aliases, or IP addresses versus a fully qualified authoritative domain name.

These duplicate dependencies increase operational complexity, create configuration drift, and complicate audits and troubleshooting. This script provides a controlled and auditable method to identify and remediate these duplicates.

The script performs the following high-level actions:

1. Identifies dependencies discovered using alias domains  
2. Compares them against authoritative dependencies  
3. Merges selected configuration differences into the authoritative dependency  
4. Deletes the alias dependency  
5. Preserves audit history by updating existing objects rather than recreating them  

The script is safe by default. No changes are made unless explicitly approved using the Apply parameter, and a dry-run plan is always generated first.

## Supported Platforms

### CyberArk Deployments

- Privilege Cloud (ISPSS)
- PAM Self-Hosted

### Dependency Types Validated

- Windows Services (WinService)
- Scheduled Tasks
- IIS Application Pools

Other dependency types may function but are not formally validated.

## How Duplicate Detection Works

Duplicate detection does not rely on dependency names alone. Instead, a canonical identity is built for each dependency using the following attributes:

- Dependency type (service, task, IIS, etc.)
- Target machine
- Target object (service name, task path, application pool)
- Normalized username with domain information removed

Domain values are intentionally excluded from the matching logic. If two dependencies differ only by domain, they are considered candidates for deduplication.

## Alias and Authoritative Domain Mapping

Customers must define which domains are considered aliases and which domain is authoritative. This mapping is used only for comparison and is never merged back into authoritative dependencies.

Example alias mapping file:

```json
{
  "CORP": "corp.domain.com",
  "corp": "corp.domain.com",
  "corp.local": "corp.domain.com",
  "10.0.0.1": "corp.domain.com"
}
```

The alias mapping can be provided using one of the following options:

- AliasMapPath (path to a JSON file)
- AliasMap (inline PowerShell hashtable)

## Safety and Change Control Model

This script is designed with production safety as a primary requirement.

Built-in safeguards include:

- Dry-run mode by default
- Explicit Apply parameter required to make changes
- Interactive confirmation prompt unless Force is specified
- Merge and delete safety caps
- Full JSON archival of alias dependencies prior to deletion
- Detailed REST error logging
- Post-merge verification of updated dependencies
- Resume capability from a previously approved dry-run plan

Customers should always review the dry-run CSV before applying changes.

## Requirements and Permissions

- Windows PowerShell 5.1 or PowerShell 7 or later
- Network access to the PVWA endpoint
- Permissions to:
  - Read accounts
  - Read dependent accounts
  - Update dependent accounts
  - Delete dependent accounts

Read-only permissions are sufficient to perform a dry run.

## Authentication Methods

Authentication may be performed using one of the following methods:

### Bearer Token Authentication

A pre-acquired bearer token may be supplied to the script. This is the recommended approach for automation and service-based execution.

### Classic PVWA Authentication

The script also supports classic PVWA authentication using a PSCredential object and an AuthType parameter such as CyberArk, LDAP, or RADIUS.

## Common Operational Scenarios

### Scenario 1: First-Time Safe Dry Run (Recommended)

```powershell
.\cyberark-discovery-dependency-deduper.ps1 `
  -PVWAUrl https://tenant.privilegecloud.cyberark.cloud `
  -BearerToken <token> `
  -SafeFilter "Finance-Safe" `
  -AliasMapPath .\alias.json
```

What happens:

- No changes are made
- dry-run.csv is generated
- You can review exactly what would be merged and deleted

### Scenario 2: Merge Only One Setting (Most Common)

Example: the alias dependency has restartService = Yes, but the authoritative dependency does not.

```powershell
.\cyberark-discovery-dependency-deduper.ps1 `
  -PVWAUrl https://tenant.privilegecloud.cyberark.cloud `
  -BearerToken <token> `
  -AliasMapPath .\alias.json `
  -OnlyMergeKeys platformDependentProperties.restartService `
  -Apply
```

### Scenario 3: Controlled Production Execution (Safety Caps)

```powershell
.\cyberark-discovery-dependency-deduper.ps1 `
  -PVWAUrl https://tenant.privilegecloud.cyberark.cloud `
  -BearerToken <token> `
  -AliasMapPath .\alias.json `
  -Apply `
  -MaxMerges 10 `
  -MaxDeletes 10
```

Why this is useful:

- Limits blast radius
- Ideal for phased rollout
- Can be re-run safely

### Scenario 4: Resume From an Approved Plan

Use this after a dry run has been reviewed and approved. This executes only the rows in the prior dry-run.csv.

```powershell
.\cyberark-discovery-dependency-deduper.ps1 `
  -PVWAUrl https://tenant.privilegecloud.cyberark.cloud `
  -BearerToken <token> `
  -ResumeFrom .\out\20260110_120004\dry-run.csv `
  -Apply
```

### Scenario 5: Apply Changes Without an Interactive Prompt

```powershell
.\cyberark-discovery-dependency-deduper.ps1 `
  -PVWAUrl https://tenant.privilegecloud.cyberark.cloud `
  -BearerToken <token> `
  -AliasMapPath .\alias.json `
  -Apply `
  -Force
```


### Initial Dry Run

Customers are strongly encouraged to begin with a dry run scoped to a limited set of Safes. This allows validation of duplicate detection logic and review of proposed changes without modifying the environment.

### Controlled Production Execution

After reviewing and approving the dry-run output, changes may be applied using conservative merge and delete caps to limit operational impact.

### Resume from Approved Plan

Previously reviewed dry-run plans may be resumed directly, ensuring deterministic execution without rediscovery.

## Merge Behavior

Platform-dependent properties may be merged from the alias dependency into the authoritative dependency. The LogonDomain property is explicitly excluded from all merge operations to prevent reintroducing alias domains.

Selective merging may be enforced using the OnlyMergeKeys parameter, which supports wildcard patterns.

## Output Artifacts

Each execution generates a timestamped output directory containing:

- dry-run.csv: Proposed merges and deletions
- actions.log: Human-readable execution log
- errors.jsonl: Detailed REST error records
- summary.csv: Per-account merge and delete statistics
- post-state.csv: Final authoritative state after changes
- raw directory: API response snapshots
- archive directory: JSON backups of deleted dependencies

## When Not to Use This Script

This script should not be used if the authoritative domain has not been clearly identified, if alias domains represent intentional security boundaries, or if discovery behavior has not been fully reviewed.

## Conclusion

When used as intended, the CyberArk Discovery Dependency Deduper improves discovery hygiene, reduces duplicate configuration artifacts, and enhances operational clarity while preserving audit integrity and change control.
