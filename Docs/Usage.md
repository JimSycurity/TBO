# Titanis.TBO.Smb2 PowerShell Module

This module provides the TBO SMB2 PowerShell provider and cmdlets for backup-operator workflows.

## Quick Start

```powershell
Import-Module .\Titanis.TBO.Smb2.psd1 -Force

Set-TBOSmbConnectOptions `
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

Use `Get-Help about_TBO_Smb2_Provider` for supported item types, dynamic parameters, and limitations (for example, content writing is not implemented).

On Windows, `Get-Acl` and `Set-Acl` work with `tbo:\` and provider-qualified UNC paths. Snapshot paths are read-only.

## Provider (TBO.Reg) (Preview)

The `TBO.Reg` provider exposes the remote registry through a per-server PSDrive. The drive root is the server name, and the top-level items are hives (HKLM, HKCU, HKU, etc). Keys enumerate subkeys by default; use `-IncludeValues` (or `-IncludeData`) to include values. The default value is shown as `(Default)`.

```powershell
New-PSDrive -Name tbo-reg -PSProvider 'TBO.Reg' -Root corp1-web01.corp1.lab.home-labs.lol
Get-ChildItem tbo-reg:\
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
Disconnect-TBOSmbServer -All
```

### Set-TBOSmbConnectOptions

Sets connection defaults used by TBO cmdlets and the TBO.Smb2 provider. Supports the same dynamic parameters as `New-PSDrive` (credentials, SMB dialects, ciphers, signing, name resolution, and more).

```powershell
Set-TBOSmbConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -HostName corp1-web01.corp1.lab.home-labs.lol -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -Password 'YourSecurePassword'
Set-TBOSmbConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -NtlmHash "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
Set-TBOSmbConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -TicketCache C:\temp\krb5cc
Set-TBOSmbConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -AesKey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -Kdc corp1-dc01.corp1.lab.home-labs.lol
```

### Set-TBORegConnectOptions

Sets connection defaults used by the TBO.Reg provider and remote registry cmdlets. Accepts the same dynamic parameters as `Set-TBOSmbConnectOptions`.

```powershell
Set-TBORegConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -HostName corp1-web01.corp1.lab.home-labs.lol -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -Password 'YourSecurePassword'
Set-TBORegConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -NtlmHash "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
Set-TBORegConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -TicketCache C:\temp\krb5cc
Set-TBORegConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -AesKey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -Kdc corp1-dc01.corp1.lab.home-labs.lol
```

### Copy-TBOSmbItem

Copies files between local paths and SMB paths using backup intent. Supports UNC or `tbo:\` paths. Use `-Force` (alias `-Overwrite`) to overwrite existing destinations.

```powershell
Copy-TBOSmbItem -Source tbo:\Windows\System32\config\SAM -Destination C:\Temp\SAM.bak
Copy-TBOSmbItem -Source C:\Temp\local.txt -Destination tbo:\Temp\local.txt -CreateDirectories
Copy-TBOSmbItem -Source C:\Temp\local.txt -Destination tbo:\Temp\local.txt -Force
```

### Get-TBOSmbSnapshots

Lists available VSS snapshots for a file or directory.

```powershell
Get-TBOSmbSnapshots -Path tbo:\Windows\System32\config\SAM
Get-TBOSmbSnapshots -Path \\corp1-web01\C$\Windows\System32\config\SAM
Set-Location tbo:\@GMT-2026.01.25-20.47.30\Windows\System32\config
```

### Get-TBOSmbStreams

Lists the data streams of a file or directory.

```powershell
Get-TBOSmbStreams -Path tbo:\Temp\local.txt
Get-TBOSmbStreams -Path \\corp1-web01.corp1.lab.home-labs.lol\C$\Temp\local.txt
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
Get-TBOSmbShares -ServerName corp1-web01.corp1.lab.home-labs.lol
Get-TBOSmbShares -ServerName corp1-web01.corp1.lab.home-labs.lol -Level Level1
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
When using UNC paths, the server name must match the name used in `Set-TBOSmbConnectOptions` (for example, FQDN vs short name). A mismatch can yield "context does not match any mechanisms supported by the server."
Use `-Sections` to control which components are retrieved (default: Owner, Group, DACL).

```powershell
$sd = Get-TBOSmbSecurityDescriptor -Path tbo:\Windows
$sddl = Get-TBOSmbSecurityDescriptor -Path \\corp1-web01\C$\Windows -AsSddl
$winSd = Get-TBOSmbSecurityDescriptor -Path tbo:\Windows -AsWindows
$daclOnly = Get-TBOSmbSecurityDescriptor -Path tbo:\Windows -Sections Dacl
```

### Set-TBOSmbSecurityDescriptor

Writes a security descriptor to a file or directory from a portable `SecurityDescriptor`.
Use `-Sections` to limit which parts of the descriptor are applied (default: Owner, Group, DACL).
The input can be a portable `SecurityDescriptor`, an SDDL string, raw bytes, or Windows security descriptor objects. SDDL and Windows descriptor inputs are Windows-only; on Linux use portable or raw bytes.

```powershell
$sd = Get-TBOSmbSecurityDescriptor -Path tbo:\Windows
Set-TBOSmbSecurityDescriptor -Path tbo:\Windows -SecurityDescriptor $sd
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

### Remote Registry Cmdlets (MS-RRP)

Remote registry cmdlets use the winreg pipe with backup/restore semantics on every open.

#### Get-TBORegKey

Gets metadata for a remote registry key.

```powershell
Get-TBORegKey -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE
Get-TBORegKey -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE -IncludeClass
```

#### Get-TBORegSessions

Enumerates user session SIDs from HKEY_USERS on the remote host. SYSTEM SIDs are excluded by default.

```powershell
Get-TBORegSessions -ServerName corp1-web01.corp1.lab.home-labs.lol
```

#### Get-TBORegChildItem

Lists subkeys and values beneath a remote registry key.

```powershell
Get-TBORegChildItem -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE
Get-TBORegChildItem -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE -IncludeValues -IncludeData
Get-TBORegChildItem -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE -IncludeSubkeys
```

#### New-TBORegKey

Creates a remote registry key.

```powershell
New-TBORegKey -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO
```

#### Remove-TBORegKey

Removes a remote registry key.

```powershell
Remove-TBORegKey -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO
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
Set-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO -Name InstallId -Type String -Value "abc123"
Set-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO -Name Flags -Type DwordLE -Value 1
```

#### Remove-TBORegValue

Removes a remote registry value.

```powershell
Remove-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO -Name InstallId
```

## Local Logging

Set `TITANIS_TBO_LOG` to `1` or to a file path. When set to `1`, logs go to
`%TEMP%\Titanis.TBO.Smb2.log`.

## Build

```powershell
# Bump the version (major|minor|patch) before commit.
.\Build\Update-Version.ps1 -Bump patch

# Build with PSPublishModule.
.\Build\Build-Module.ps1 -Configuration Release
```
