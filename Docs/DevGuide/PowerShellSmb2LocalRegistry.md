# PowerShell Local Registry Mode (Backup/Restore Intent)

## Goal
Allow the existing `TBO.Reg` PSProvider and the `Get/New/Remove/Set-TBOReg*` cmdlets to operate against the *local* registry (no MS-RRP, no SMB) while preserving the project rule that operations should be performed with backup/restore intent whenever possible.

This is analogous to the local NTFS mode added under `tbo-local:` for `TBO.Smb2`.

## Non-Goals
- Support on non-Windows platforms.
- Offline hive parsing (reading `SYSTEM`, `SAM`, `SECURITY` files directly).
- Registry snapshot navigation (VSS-backed registry reads).

## Proposed UX
Cmdlets:

```powershell
Get-TBORegKey -ServerName localhost -Path HKLM\SOFTWARE
Get-TBORegChildItem -ServerName localhost -Path HKLM\SOFTWARE -IncludeValues
```

Provider:

```powershell
New-PSDrive -Name tbo-reg-local -PSProvider 'TBO.Reg' -Root localhost
Get-ChildItem tbo-reg-local:\HKLM\SOFTWARE -IncludeValues
```

## Local-Mode Routing
All registry operations currently flow through `RegistryRetryHelper.Execute(...)`, which opens an `IRegistrySession` whose `Client` implements `IRegistryClient` and returns `IRegistryKey` objects.

To minimize refactoring:
- Add a local routing branch in `RegistryRetryHelper.OpenRegistrySession(...)`.
- When `-ServerName localhost` is used, return a `LocalRegistrySession` rather than opening a remote winreg session.

The remainder of the cmdlet/provider logic should stay unchanged.

## Local Backend Shape
Implement a local backend that satisfies the same Titanis MS-RRP interfaces used by the module:
- `LocalRegistrySession : IRegistrySession, IRegistrySecretCacheProvider`
- `LocalRegistryClient : IRegistryClient`
- `LocalRegistryKey : IRegistryKey`

This mirrors the approach already used by `FakeRegistryStore` (in-memory implementation), except backed by Win32 registry handles.

## Win32 Implementation Notes
Preferred implementation is `advapi32.dll` P/Invoke with `SafeRegistryHandle`.

Key operations needed:
- Open root keys: `HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`, `HKEY_USERS`, etc.
- Open subkeys (read-only path) without creating missing keys.
- Create subkeys for write scenarios.
- Enumerate subkeys and values.
- Get/set/delete values.
- Query key metadata (subkey count, value count, max lengths, last write time).
- Query and set key security descriptors (owner/group/dacl/sacl).

### Backup/Restore Intent
Remote registry operations use `RegistryKeyOptions.BackupRestore` (protocol option `REG_OPTION_BACKUP_RESTORE`).

For local mode, the implementation should:
- Enable `SeBackupPrivilege` / `SeRestorePrivilege` before key open/create when `BackupRestore` is requested.
- Enable `SeSecurityPrivilege` only when SACL is requested (SecurityInfo includes SACL).
- Use Win32 APIs that support `REG_OPTION_BACKUP_RESTORE` (`RegCreateKeyEx`) when backup/restore semantics are required.

Implementation notes:
- `RegOpenKeyEx` is used as a no-side-effects existence test (it cannot create missing keys).
- If access is denied and `BackupRestore` is requested, fall back to `RegCreateKeyEx` with `REG_OPTION_BACKUP_RESTORE` after enabling the relevant token privileges.
- For create operations, `RegCreateKeyEx` is used directly.

### Registry View (WOW64)
Registry access can be impacted by 32/64-bit view redirection.

To keep local output consistent with remote MS-RRP behavior, local mode defaults to the **64-bit registry view** on 64-bit hosts unless the caller explicitly requests `KEY_WOW64_32KEY`/`KEY_WOW64_64KEY` (via `RegistryAccessRights.Wow64_Use32/Wow64_Use64`).

## Logging and Errors
- Use existing module logging helpers (`LogDiagnostic`, `LogWarning`, `LogException`) for consistency.
- Preserve Win32 error codes in thrown exceptions (use `Win32Exception` where possible) so existing error handling remains useful.

## Follow-Ups
- Local registry SACL support is deferred to `TBO-twi.9`.
- Supporting additional local aliases (for example `.` or `127.0.0.1`) is tracked as `TBO-twi.10`.

## Manual Test Checklist

Read:

```powershell
Get-TBORegKey -ServerName localhost -Path HKLM\SOFTWARE
Get-TBORegChildItem -ServerName localhost -Path HKLM\SOFTWARE -IncludeValues -IncludeData
```

Write (use a safe HKCU path):

```powershell
New-TBORegKey -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test
Set-TBORegValue -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test -Name InstallId -Type String -Value "abc123"
Get-TBORegValue -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test -Name InstallId
Remove-TBORegValue -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test -Name InstallId
Remove-TBORegKey -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test
```

Security descriptors (Owner/Group/DACL; SACL deferred):

```powershell
$sd = Get-TBORegSecurityDescriptor -ServerName localhost -Path HKCU\SOFTWARE -Sections Dacl
Set-TBORegSecurityDescriptor -ServerName localhost -Path HKCU\SOFTWARE\TBO-Test -SecurityDescriptor $sd -Sections Dacl
```
