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

### Pre-flight (Any Shell)
1. Enable provider logging (optional, recommended for troubleshooting):
   ```powershell
   $env:TITANIS_TBO_LOG = "Diagnostic" # or "Debug"
   ```
2. Import the module (adjust path if you are testing from an installed module):
   ```powershell
   Import-Module .\Titanis.TBO.Smb2.psd1 -Force
   ```

### SYSTEM Scenario
1. Start a SYSTEM shell:
   - Example (Sysinternals PsExec): `psexec -s -i powershell.exe`
2. Create a local-mode drive:
   ```powershell
   New-PSDrive -Name tbo-local -PSProvider TBO.Smb2 -Root \\localhost\C$
   ```
3. Enumerate a protected directory (should work with backup semantics):
   ```powershell
   Get-ChildItem tbo-local:\Windows\System32\config | Select-Object Name, Length, Attributes
   ```
4. Get a security descriptor from a protected file:
   ```powershell
   Get-TBOSmbSecurityDescriptor -Path tbo-local:\Windows\System32\config\SAM -AsSddl -Sections Owner,Group,Dacl
   ```
   Note: Provider `Get-Content`/`Set-Content` are text-oriented (via `StreamReader`/`StreamWriter`). Avoid using them against binary hive files like `SAM` unless you only need a non-destructive "can open the file" check.
5. Get and set a security descriptor (round-trip) on a safe test target:
   ```powershell
   $testDir = 'tbo-local:\Windows\Temp\tbo-ilz-test'
   $testFile = Join-Path $testDir 'file.txt'

   New-Item -Path $testDir -ItemType Directory -Force | Out-Null
   New-Item -Path $testFile -ItemType File -Force | Out-Null
   Set-Content -Path $testFile -Value 'tbo local mode'

   $dacl = Get-TBOSmbSecurityDescriptor -Path $testFile -AsSddl -Sections Dacl
   Set-TBOSmbSecurityDescriptor -Path $testFile -SecurityDescriptor $dacl -Sections Dacl
   ```

### TrustedInstaller Scenario
1. Start a PowerShell session as `TrustedInstaller` using your preferred launcher (not shipped with this project).
2. Create a local-mode drive:
   ```powershell
   New-PSDrive -Name tbo-local -PSProvider TBO.Smb2 -Root \\localhost\C$
   ```
3. Enumerate a location that is commonly owned by `TrustedInstaller`:
   ```powershell
   Get-ChildItem tbo-local:\Windows\servicing | Select-Object -First 10 Name, Attributes
   ```
4. Validate security descriptor read on a servicing file:
   ```powershell
   Get-TBOSmbSecurityDescriptor -Path tbo-local:\Windows\servicing\TrustedInstaller.exe -AsSddl -Sections Owner,Group,Dacl
   ```
5. Optionally, repeat the safe DACL round-trip test from the SYSTEM scenario to validate `Set-TBOSmbSecurityDescriptor` from this context.

### Limit / Negative Tests (Optional)
1. Snapshot/time-warp tokens are not supported in local mode (tracked separately as `TBO-ilz.12`):
   ```powershell
   Get-ChildItem TBO.Smb2::\\localhost\C$\@GMT-2001.01.01-00.00.00\Windows
   ```
2. Non-admin shares (ex: `ADMIN$`, `IPC$`) are rejected for local mode:
   ```powershell
   New-PSDrive -Name tbo-admin -PSProvider TBO.Smb2 -Root \\localhost\ADMIN$
   ```
