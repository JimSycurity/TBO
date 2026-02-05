# Titanis.TBO.Smb2 PowerShell Module

This module provides the TBO SMB2 PowerShell provider and cmdlets for backup-operator workflows.

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

Note: Root listings (`tbo:\` or `TBO.Smb2::\\server\share`) skip reparse metadata by default. Use `-IncludeRootReparseInfo` (alias `-RootReparseInfo`) on `New-PSDrive` or `Set-TBOConnectOptions` to enable it.

## Local Logging

Set `TITANIS_TBO_LOG` to `1` or to a file path. When set to `1`, logs go to
`%TEMP%\Titanis.TBO.Smb2.log`.

## Build

```powershell
# Bump the version (major|minor|patch) before commit.
..\Build\Update-Version.ps1 -Bump patch

# Build with PSPublishModule.
..\Build\Build-Module.ps1 -Configuration Release
```
