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
- When the target `serverName` is local, return a `LocalRegistrySession` rather than opening a remote winreg session.

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
- Request the closest equivalent to `REG_OPTION_BACKUP_RESTORE` via Win32 APIs where supported.

Note: Some Win32 APIs document option parameters as "reserved" for `RegOpenKeyEx`. Validate the correct open path during implementation (see TBO-twi.3).

### Registry View (WOW64)
Registry access can be impacted by 32/64-bit view redirection.

Initial implementation should follow process default behavior (no explicit `KEY_WOW64_*` flags). If parity with remote behavior requires forcing a specific view, add that as a follow-up issue rather than guessing.

## Logging and Errors
- Use existing module logging helpers (`LogDiagnostic`, `LogWarning`, `LogException`) for consistency.
- Preserve Win32 error codes in thrown exceptions (use `Win32Exception` where possible) so existing error handling remains useful.

## Open Questions
1. Local server name detection:
   - Should local mode trigger for `localhost` only, or also `.` / machine name / `127.0.0.1` / `::1`?
2. Backup/restore open semantics:
   - Which Win32 open/create pattern gives the closest behavior to remote `BackupRestore` semantics without creating missing keys?
3. Security descriptor support:
   - Do we want to support SACL reads/writes when `SeSecurityPrivilege` is present, or treat SACL as a separate future enhancement?

