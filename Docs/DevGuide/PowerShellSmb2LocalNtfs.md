# PowerShell SMB2 Provider: Local NTFS "Backup Intent" Mode

## Goal
Extend the existing `TBO.Smb2` provider and related cmdlets to support the *local*
NTFS filesystem using backup/restore semantics, so we can:
- Open files/directories using `SeBackupPrivilege` and `SeRestorePrivilege`.
- Browse protected locations (SYSTEM/TrustedInstaller scenarios are a valid proof).
- Get and set security descriptors (DACL/Owner/Group at minimum, SACL optionally).
- Reuse the existing `UncPath` and provider UX without introducing a new provider.

This is Windows-only.

## Why UNC For Local
Most file-oriented code in this repo is built around `UncPath` and the `TBO.Smb2`
provider. For local support, we intentionally use admin-share-style UNC paths:

`\\localhost\C$\Windows\System32`

Even though this is not "real SMB", it keeps:
- Parameter shapes stable (`-Path` stays a UNC or provider-qualified path).
- Minimal changes to existing cmdlets and provider glue.
- A consistent PSDrive story (`New-PSDrive -PSProvider TBO.Smb2 ...`).

## User-Facing UX
### Path Convention
Local mode is expressed using an admin share for the local host:
- `\\localhost\<DriveLetter>$\...` maps to `<DriveLetter>:\...`

Examples:
- `\\localhost\C$\Windows\System32\config\SAM`
- `\\.\C$\Windows\Temp`
- `\\127.0.0.1\C$\Windows`

### PSDrive
Create a local-mode drive using the existing provider:

```powershell
New-PSDrive -Name tbo-local -PSProvider TBO.Smb2 -Root \\localhost\\C$
Get-ChildItem tbo-local:\\Windows\\System32
```

## Local Host Detection
Local mode is enabled when the UNC host is considered local. The implementation
should be deterministic and avoid DNS surprises.

Acceptable local host values:
- `localhost`
- `.`
- `127.0.0.1`
- `::1`
- `Environment.MachineName` (case-insensitive)

Optional (future): treat names that resolve to loopback as local.

## Share Mapping Rules
To keep the mapping simple and predictable:
- Only `<DriveLetter>$` is supported for local mode.
- `C$` maps to `C:\`, `D$` maps to `D:\`, etc.
- Other shares (ex: `ADMIN$`, `IPC$`) are rejected for local mode in v1.

The share-relative path is appended to the drive root after normalizing separators.
The implementation should reject path traversal (ex: `..\`) after resolution.

## Privileges and Semantics
### Required Privileges
Local mode assumes the caller has rights assigned and enabled:
- `SeBackupPrivilege` for backup reads.
- `SeRestorePrivilege` for backup writes (restore intent).

SACL support (if implemented) also requires:
- `SeSecurityPrivilege` for `ACCESS_SYSTEM_SECURITY`.

### Privilege Enabling
Local mode should attempt to enable privileges on the current process token via
`AdjustTokenPrivileges`. Behavior:
- If a privilege is present but disabled, enable it and log `Diagnostic`.
- If not present (`ERROR_NOT_ALL_ASSIGNED`), log a clear warning and treat backup
  semantics as unavailable (operations that rely on it should fail with guidance).

## Implementation Strategy
### Local Open (CreateFileW)
Use `CreateFileW` to open files/directories with backup semantics:
- Always set `FILE_FLAG_BACKUP_SEMANTICS`.
- Use `FILE_FLAG_OPEN_REPARSE_POINT` when the operation must target the link
  itself instead of the target.
- Use `FileShare.Read | FileShare.Write | FileShare.Delete` (match SMB provider).
- Do not rely on `GENERIC_ALL`. Request only the specific rights needed for the
  operation (ex: `READ_CONTROL`, `WRITE_DAC`, `FILE_READ_DATA`, etc).

This mirrors the "grant appropriate accesses before checking DACL" behavior of
SMB2 backup intent, but with local Windows primitives.

### Directory Enumeration (NtQueryDirectoryFile)
Enumeration must be handle-based to keep backup semantics:
- Open directory handle with backup semantics.
- Enumerate entries using `NtQueryDirectoryFile`.
- Populate `Smb2DirEntry` so existing code (and `SmbItem`) can keep working.

Existing code patterns to support:
- Pattern is effectively always `"*"` (wildcard filtering can be done in managed code).
- Options used today: `None` and `QueryReparseInfo`.
- `SecurityInfo.None` for enumeration.

### Reparse Points
For parity with provider behavior:
- At minimum, `FileAttributes.ReparsePoint` must be accurate from enumeration.
- Optional: implement tag/target resolution with `FSCTL_GET_REPARSE_POINT` for
  `Get-ChildItem` output (symbolic links, mount points, junctions).

### Security Descriptors (Get/Set)
Local-mode SD operations should mirror the SMB provider surfaces:
- Provider `Get-Acl`/`Set-Acl` through `ISecurityDescriptorCmdletProvider`.
- Cmdlets `Get-TBOSmbSecurityDescriptor` / `Set-TBOSmbSecurityDescriptor`.

Implementation approach:
- Read SD bytes from a handle using `GetSecurityInfo` (or equivalent).
- Write SD sections using `SetSecurityInfo`.
- Convert between Windows SD bytes and Titanis portable SD types using existing
  helpers (`SecurityDescriptorHelpers` and `SecurityDescriptorInputHelpers`).

### Provider Routing
`TBO.Smb2` should route operations based on "local-mode" predicate:
- If local-mode: do not use `Smb2Client` at all.
- If remote: keep existing SMB behavior.

Key provider entry points to update:
- `NewDrive`: skip SMB connect for local-mode roots.
- `GetChildItems`/`ItemExists`/`IsItemContainer`: use local enumeration/opens.
- `GetContentReader`/`GetContentWriter`/`ClearContent`: use local streams.
- `NewItem`/`RemoveItem`: use local create/delete semantics.
- Security descriptor methods: use local SD get/set.

Snapshot/time-warp behavior is SMB-specific; local-mode should reject snapshot
tokens initially with a clear error.

## Phased Delivery
1. Design and host/share mapping rules.
2. Privilege enable/detect helper.
3. Local open wrapper (`CreateFileW`) with backup semantics.
4. Handle-based enumeration (`NtQueryDirectoryFile`).
5. Provider navigation + PSDrive local-mode.
6. Security descriptor get/set for local-mode.
7. Write operations (content write, create/remove) for local-mode.
8. Optional: integrate local-mode into `ISmbFileSystem` for DPAPI/Chrome tooling.

## Manual Test Cases
These are manual validation steps (not automated tests).

1. Start a SYSTEM shell and create a local-mode drive:
   - Example: `psexec -s -i powershell.exe`
   - `New-PSDrive -Name tbo-local -PSProvider TBO.Smb2 -Root \\localhost\\C$`
2. Enumerate a protected directory:
   - `Get-ChildItem tbo-local:\\Windows\\System32\\config`
3. Read a protected file (proof of backup semantics):
   - `Get-Content -Raw -Encoding Byte tbo-local:\\Windows\\System32\\config\\SAM | Measure-Object`
4. Get and set a security descriptor (use a safe test target):
   - Create `tbo-local:\\Windows\\Temp\\tbo-ilz-test` and operate there.
   - `Get-Acl tbo-local:\\Windows\\Temp\\tbo-ilz-test`
   - `Set-Acl ...` (validate round-trip, do not weaken security on system folders)
5. Enable logging for diagnostics:
   - Set `TITANIS_TBO_LOG=Debug` (or `Diagnostic`) and inspect the log in `%TEMP%`.

