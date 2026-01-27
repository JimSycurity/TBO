# PowerShell SMB2 + Remote Registry (Backup-Privilege-First)

## Goal
Provide a PowerShell module that exposes SMB2 and MS-RRP capabilities with a
strict requirement: every connection, read, and write is performed using backup
semantics (protocol backup intent + SeBackupPrivilege/SeRestorePrivilege on the
remote token).

This note describes a mixed provider/cmdlet design that enforces those rules.

## Non-Goals
- No interactive credential prompting design in this phase.
- No UI/formatting work beyond basic cmdlet output.
- No provider for Remote Registry in v1 (cmdlets only).

## Principles (Hard Requirements)
1. All SMB2 create/open requests set `Smb2FileCreateOptions.OpenForBackupIntent`.
2. All Remote Registry opens use `RegistryKeyOptions.BackupRestore`.
3. Security descriptors are handled as .NET objects with a portable
   representation (Windows-specific ACL types only as adapters).
4. Every operation assumes the remote account has SeBackupPrivilege and
   SeRestorePrivilege enabled in the server-side token.

## Backup-Privilege Enforcement
The module must treat backup/restore semantics as non-optional:
- SMB2: set `OpenForBackupIntent` on every create/open.
- MS-RRP: set `BackupRestore` on every key open/creation.
- Auth token: the module assumes SeBackupPrivilege and SeRestorePrivilege are
  already enabled for the remote account. It does not attempt LSARPC privilege
  checks or auto-grant (Backup Operators are not local admins).

## Protocol Flags Summary
- SMB2: FILE_OPEN_FOR_BACKUP_INTENT
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997
- MS-RRP: REG_OPTION_BACKUP_RESTORE
  https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexa
- Certificate stores (future use): CERT_STORE_BACKUP_RESTORE_FLAG
  https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
- Local files (future use): FILE_FLAG_BACKUP_SEMANTICS
  https://learn.microsoft.com/en-us/dotnet/api/microsoft.build.experimental.fileaccess.flagsandattributes?view=msbuild-17-netcore

## Architecture Overview

### Module Structure
- **SMB2 provider** for navigation and basic operations:
  - `Get-ChildItem`, `Get-Item`, `New-Item`, `Remove-Item`, `Get-Content`, etc.
  - Uses Titanis SMB2 APIs with backup intent on every open/create.
- **Advanced SMB2 cmdlets** for explicit operations:
  - `Copy-TBOSmbItem` (backup-aware read/write)
  - `Get-TBOSmbSecurityDescriptor`, `Set-TBOSmbSecurityDescriptor`
  - `Connect-TBOSmbServer`, `Set-TBOSmbConnectOptions`
- **Remote Registry cmdlets** (MS-RRP over the winreg pipe):
  - `Get-TBORegKey`, `New-TBORegKey`, `Remove-TBORegKey`
  - `Get-TBORegValue`, `Set-TBORegValue`, `Remove-TBORegValue`
  - `Get-TBORegSecurityDescriptor`, `Set-TBORegSecurityDescriptor`

### Connection and Session Context
- A shared connection context stores credentials, target host, and defaults.
- A single policy flag indicates "backup-only mode"; this must be enforced for
  every operation and cannot be disabled by users.

### Local Logging
Set `TITANIS_TBO_LOG` to enable SMB2 trace logging for the provider:
- `TITANIS_TBO_LOG=1` (or `true`/`yes`) writes to `%TEMP%\Titanis.TBO.Smb2.log`.
- `TITANIS_TBO_LOG=<path>` writes to the specified file.
Logs include connect/session/share events and DFS referral activity.

## SMB2 Provider (Backup-Only)
Provider operations must set backup intent on all opens/creates:
- Use `Smb2FileCreateOptions.OpenForBackupIntent` for both files and directories.
- For directory enumeration, ensure any internal `CreateFileAsync` or
  `OpenDirectoryAsync` paths include backup intent.
- Use appropriate access rights for backup reads/writes; do not rely on normal
  ACL access checks.

### Provider Limits
Operations that do not translate cleanly to backup intent should be implemented
as explicit cmdlets (e.g., copy or security descriptor updates).

## SMB2 Advanced Cmdlets
Cmdlets allow explicit control of behavior and clearer error handling:
- `Get-SmbSecurityDescriptor` / `Set-SmbSecurityDescriptor`:
  - Read/write SDs using Titanis SMB2 APIs.
  - Output a portable SecurityDescriptor object (see below).
- `Copy-SmbItem`:
  - Always open source and destination with backup intent.
  - Preserve metadata and security descriptors when requested.

## Remote Registry (MS-RRP)
Remote registry operations should use the new MS-RRP implementation:
- Open keys with `RegistryKeyOptions.BackupRestore`.
- Access rights should align with backup/restore semantics rather than standard
  ACL evaluation.
- Registry security descriptors should be read/written as portable SD objects.
- Use the winreg pipe and standard root key naming (HKLM, HKU, etc.) for
  user-facing paths.

### Cmdlet Naming
Cmdlets must not collide with built-in cmdlets or those from other modules. Use
the `TBO` prefix (Titanis Backup Operator) on the noun and standard
verb-noun syntax for all net-new cmdlets.

SMB2 advanced and connection cmdlets follow the same rule:
`*-TBOSmb*` for any net-new SMB2 cmdlets.

## Security Descriptor Strategy
Use Titanis' portable security descriptor types as the module contract:
- `Titanis.Winterop.Security.SecurityDescriptor`
- `Titanis.Winterop.Security.AccessControlList`
- `Titanis.Winterop.Security.SecurityIdentifier`

Expose multiple representations:
- **Object**: portable SecurityDescriptor object (default).
- **SDDL**: string (`-AsSddl`).
- **Raw**: byte array (`-AsBytes`).

On Windows, optionally provide adapters to `System.Security.AccessControl`
types, but do not require them for module core behavior.

## Cross-Platform Behavior
- The module should function on PowerShell Core (Linux/macOS) without relying on
  Windows-only ACL classes.
- SDDL and raw SD bytes remain valid interchange formats across platforms.

## Open Questions / Risks
1. How to guarantee server-side privileges are enabled for the remote account
   across SMB2 and MS-RRP flows.
   Answer: The module does not perform LSARPC checks or auto-grant. It assumes the
   account already has SeBackupPrivilege and SeRestorePrivilege enabled and relies
   on protocol-level backup intent for access.
2. Whether any SMB2 or MS-RRP operations require additional flags or access
   rights beyond backup/restore intent.
   Answer: In testing with BackupOperatorToolkit, no additional flags were required beyond
   backup intent. The current plan relies on the flags listed above and treats certificate
   store and local file flags as future expansions, not v1 requirements.
3. How to handle cases where the remote server ignores backup intent (policy or
   configuration).
   Answer: Treat this as a hard failure with a clear error and diagnostic guidance.
