# TBO
## Titanis Backup Operator
Titanis Backup Operator is a PowerShell module and PSProvider written (mostly by OpenAI codex) in C#. It is a set of tools that utilize the TrustedSec [Titanis](https://github.com/trustedsec/Titanis) as the underlying Windows protocol library to interact with remote systems over SMB and Remote Registry with all interactions utilizing backup intent flags along with SeBackupPrivilege and SeRestorePrivilege active in the token. This means that security descriptors on the directories, files, and registry keys are bypassed completely because active privileges > granted rights.

Titanis, created by [codewhisperer84](https://github.com/codewhisperer84), is a library of protocol implementations and command line utilities written in C# for interacting with Windows environments. It is cross-platform (Windows and Linux) solution that this project relies on for MS-SMB2, MS-RPCE, MS-RRP, and security/authenitcation protocols.

The builtin console apps in Titanis can do much of the functionality in this module with some extra work and input, but I'm a PowerShell guy and love being able to use this to script out scenarios. I think Titanis is a very neat project and I hope this little bit of code will help convince other folks to build tools on top of Titanis.

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

[Usage Examples](Docs\Usage.md)


This software was written almost exclusively with the use of agentic coding. As such, it primarily contains code pilfered and regurgitated from elsewhere. However, there were specific choices to base some aspects of the code on SharpDPAPI and BackupOperatorToolkit.