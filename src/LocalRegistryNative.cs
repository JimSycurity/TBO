using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	/// <summary>
	/// Minimal local Win32 registry interop used to implement localhost-backed MS-RRP abstractions.
	/// </summary>
	internal static class LocalRegistryNative
	{
		// Predefined registry key handles (WinReg.h).
		private static readonly nint HKEY_CLASSES_ROOT = new(unchecked((int)0x80000000));
		private static readonly nint HKEY_CURRENT_USER = new(unchecked((int)0x80000001));
		private static readonly nint HKEY_LOCAL_MACHINE = new(unchecked((int)0x80000002));
		private static readonly nint HKEY_USERS = new(unchecked((int)0x80000003));
		private static readonly nint HKEY_PERFORMANCE_DATA = new(unchecked((int)0x80000004));
		private static readonly nint HKEY_CURRENT_CONFIG = new(unchecked((int)0x80000005));
		private static readonly nint HKEY_PERFORMANCE_TEXT = new(unchecked((int)0x80000050));
		private static readonly nint HKEY_PERFORMANCE_NLS_TEXT = new(unchecked((int)0x80000060));

		private const uint RegCreatedNewKey = 1;
		private const uint RegOpenedExistingKey = 2;
		private const RegistryAccessRights AccessSystemSecurity = (RegistryAccessRights)0x01000000;

		private static RegistryAccessRights NormalizeWow64Access(RegistryAccessRights access)
		{
			// Remote MS-RRP default behavior is effectively 64-bit view on 64-bit hosts unless the caller
			// requests KEY_WOW64_32KEY. Local callers may be 32-bit (WOW64) and would otherwise be redirected
			// to the 32-bit registry view, which is surprising compared to remote behavior.
			if (!Environment.Is64BitOperatingSystem)
				return access;

			var wow64 = access & (RegistryAccessRights.Wow64_Use32 | RegistryAccessRights.Wow64_Use64);
			if (wow64 != 0)
				return access;

			return access | RegistryAccessRights.Wow64_Use64;
		}

		private static nint GetPredefinedRootHandle(RegistryRootKey rootKey)
		{
			return rootKey switch
			{
				RegistryRootKey.ClassesRoot => HKEY_CLASSES_ROOT,
				RegistryRootKey.CurrentUser => HKEY_CURRENT_USER,
				RegistryRootKey.LocalMachine => HKEY_LOCAL_MACHINE,
				RegistryRootKey.Users => HKEY_USERS,
				RegistryRootKey.PerformanceData => HKEY_PERFORMANCE_DATA,
				RegistryRootKey.CurrentConfig => HKEY_CURRENT_CONFIG,
				RegistryRootKey.PerformanceText => HKEY_PERFORMANCE_TEXT,
				RegistryRootKey.PerformanceNlsText => HKEY_PERFORMANCE_NLS_TEXT,
				_ => throw new ArgumentException("Not a valid root key.", nameof(rootKey)),
			};
		}

		internal static SafeRegistryHandle OpenRootKey(
			RegistryRootKey rootKey,
			RegistryAccessRights access,
			Action<string>? logDiagnostic = null,
			Action<string>? logWarning = null)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local registry mode is only supported on Windows.");

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			var desiredAccess = NormalizeWow64Access(access);
			if (RegistryAccessRequestsSystemSecurity(desiredAccess))
			{
				EnsureSeSecurityPrivilegeEnabled(
					operation: "open key handles with ACCESS_SYSTEM_SECURITY",
					logDiagnostic,
					logWarning);
			}

			var rootHandle = GetPredefinedRootHandle(rootKey);

			// RegOpenKeyEx allows lpSubKey=null to open the key represented by hKey.
			logDiagnostic($"Local registry RegOpenKeyEx: root={RemoteRegistryClient.GetRootName(rootKey)}, access=0x{(uint)desiredAccess:X8}.");

			var res = (Win32ErrorCode)RegOpenKeyEx(rootHandle, null, 0, (uint)desiredAccess, out var handle);
			if (res != Win32ErrorCode.ERROR_SUCCESS)
				throw new Win32Exception((int)res, $"RegOpenKeyEx failed for {RemoteRegistryClient.GetRootName(rootKey)}: {res}.");

			return handle;
		}

		internal static SafeRegistryHandle OpenSubkey(
			SafeRegistryHandle parentKey,
			string subkeyPath,
			RegistryAccessRights access,
			RegistryKeyOptions options,
			Action<string>? logDiagnostic = null,
			Action<string>? logWarning = null)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local registry mode is only supported on Windows.");
			if (parentKey == null)
				throw new ArgumentNullException(nameof(parentKey));
			if (string.IsNullOrWhiteSpace(subkeyPath))
				throw new ArgumentException("Subkey path must be provided.", nameof(subkeyPath));

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			var desiredAccess = NormalizeWow64Access(access);
			if (RegistryAccessRequestsSystemSecurity(desiredAccess))
			{
				EnsureSeSecurityPrivilegeEnabled(
					operation: "open key handles with ACCESS_SYSTEM_SECURITY",
					logDiagnostic,
					logWarning);
			}

			logDiagnostic($"Local registry RegOpenKeyEx: parent=0x{parentKey.DangerousGetHandle():X}, subkey='{subkeyPath}', access=0x{(uint)desiredAccess:X8}, options=0x{(uint)options:X8}.");

			// RegOpenKeyEx is the only open call that cannot create keys. Use it first as an existence test.
			// If access is denied and BackupRestore is requested, fall back to RegCreateKeyEx with REG_OPTION_BACKUP_RESTORE.
			var openRes = (Win32ErrorCode)RegOpenKeyEx(parentKey.DangerousGetHandle(), subkeyPath, 0, (uint)desiredAccess, out var opened);
			if (openRes == Win32ErrorCode.ERROR_SUCCESS)
				return opened;

			if (openRes is Win32ErrorCode.ERROR_FILE_NOT_FOUND or Win32ErrorCode.ERROR_PATH_NOT_FOUND or Win32ErrorCode.ERROR_BAD_PATHNAME)
				throw new Win32Exception((int)openRes, $"RegOpenKeyEx failed for subkey '{subkeyPath}': {openRes}.");

			if (options == RegistryKeyOptions.None)
				throw new Win32Exception((int)openRes, $"RegOpenKeyEx failed for subkey '{subkeyPath}': {openRes}.");

			// Backup/restore options only work if the corresponding token privileges are enabled. If a privilege is
			// not assigned, the call may still succeed when normal access checks allow it.
			if (options.HasFlag(RegistryKeyOptions.BackupRestore))
			{
				LocalTokenPrivileges.EnsureBackupRestorePrivilegesEnabled(
					includeSecurityPrivilege: false,
					logDiagnostic,
					logWarning);
			}

			var createRes = (Win32ErrorCode)RegCreateKeyEx(
				parentKey.DangerousGetHandle(),
				subkeyPath,
				0,
				null,
				(uint)options,
				(uint)desiredAccess,
				IntPtr.Zero,
				out var createdHandle,
				out var disposition);

			if (createRes != Win32ErrorCode.ERROR_SUCCESS)
				throw new Win32Exception((int)createRes, $"RegCreateKeyEx failed for subkey '{subkeyPath}': {createRes}.");

			// We only use RegCreateKeyEx as an "open existing with options" fallback after a non-NOT_FOUND RegOpenKeyEx error.
			// If we get a new key here, treat it as not-found rather than silently creating keys during read operations.
			if (disposition == RegCreatedNewKey)
			{
				createdHandle.Dispose();
				logWarning($"Local registry: RegCreateKeyEx unexpectedly created '{subkeyPath}' while opening; treating as not found to avoid side effects.");
				throw new Win32Exception((int)Win32ErrorCode.ERROR_FILE_NOT_FOUND, $"Registry key not found: {subkeyPath}.");
			}

			if (disposition != RegOpenedExistingKey)
				logDiagnostic($"Local registry: RegCreateKeyEx returned unexpected disposition={disposition} for '{subkeyPath}'.");

			return createdHandle;
		}

		internal static SafeRegistryHandle CreateSubkey(
			SafeRegistryHandle parentKey,
			string subkeyName,
			RegistryAccessRights access,
			RegistryKeyOptions options,
			out bool createdNew,
			Action<string>? logDiagnostic = null,
			Action<string>? logWarning = null)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local registry mode is only supported on Windows.");
			if (parentKey == null)
				throw new ArgumentNullException(nameof(parentKey));
			if (string.IsNullOrWhiteSpace(subkeyName))
				throw new ArgumentException("Subkey name must be provided.", nameof(subkeyName));

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			var desiredAccess = NormalizeWow64Access(access);
			if (RegistryAccessRequestsSystemSecurity(desiredAccess))
			{
				EnsureSeSecurityPrivilegeEnabled(
					operation: "create key handles with ACCESS_SYSTEM_SECURITY",
					logDiagnostic,
					logWarning);
			}

			if (options.HasFlag(RegistryKeyOptions.BackupRestore))
			{
				LocalTokenPrivileges.EnsureBackupRestorePrivilegesEnabled(
					includeSecurityPrivilege: RegistryAccessRequestsSystemSecurity(desiredAccess),
					logDiagnostic,
					logWarning);
			}

			logDiagnostic($"Local registry RegCreateKeyEx: parent=0x{parentKey.DangerousGetHandle():X}, subkey='{subkeyName}', access=0x{(uint)desiredAccess:X8}, options=0x{(uint)options:X8}.");

			var res = (Win32ErrorCode)RegCreateKeyEx(
				parentKey.DangerousGetHandle(),
				subkeyName,
				0,
				null,
				(uint)options,
				(uint)desiredAccess,
				IntPtr.Zero,
				out var handle,
				out var disposition);

			if (res is Win32ErrorCode.ERROR_ACCESS_DENIED or Win32ErrorCode.ERROR_PRIVILEGE_NOT_HELD
				&& options.HasFlag(RegistryKeyOptions.BackupRestore))
			{
				// REG_OPTION_BACKUP_RESTORE can fail when backup/restore privileges are not assigned to the token,
				// even if normal access checks would allow the operation (for example under HKCU).
				// Retry without backup/restore semantics so local mode remains usable without those privileges.
				var fallbackOptions = options & ~RegistryKeyOptions.BackupRestore;
				logWarning($"Local registry: RegCreateKeyEx failed with {res} using BackupRestore; retrying with options=0x{(uint)fallbackOptions:X8}.");

				res = (Win32ErrorCode)RegCreateKeyEx(
					parentKey.DangerousGetHandle(),
					subkeyName,
					0,
					null,
					(uint)fallbackOptions,
					(uint)desiredAccess,
					IntPtr.Zero,
					out handle,
					out disposition);
			}

			if (res != Win32ErrorCode.ERROR_SUCCESS)
				throw new Win32Exception((int)res, $"RegCreateKeyEx failed for subkey '{subkeyName}': {res}.");

			createdNew = disposition == RegCreatedNewKey;
			return handle;
		}

		internal static void DeleteSubkey(
			SafeRegistryHandle parentKey,
			string subkeyName,
			RegistryAccessRights openAccess,
			Action<string>? logDiagnostic = null)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local registry mode is only supported on Windows.");
			if (parentKey == null)
				throw new ArgumentNullException(nameof(parentKey));
			if (string.IsNullOrWhiteSpace(subkeyName))
				throw new ArgumentException("Subkey name must be provided.", nameof(subkeyName));

			logDiagnostic ??= _ => { };

			var desiredAccess = NormalizeWow64Access(openAccess);
			var wow64 = desiredAccess & (RegistryAccessRights.Wow64_Use32 | RegistryAccessRights.Wow64_Use64);

			logDiagnostic($"Local registry RegDeleteKeyEx: parent=0x{parentKey.DangerousGetHandle():X}, subkey='{subkeyName}', wow64=0x{(uint)wow64:X8}.");

			var res = (Win32ErrorCode)RegDeleteKeyEx(parentKey, subkeyName, (uint)wow64, 0);
			if (res != Win32ErrorCode.ERROR_SUCCESS)
				throw new Win32Exception((int)res, $"RegDeleteKeyEx failed for subkey '{subkeyName}': {res}.");
		}

		internal static void DeleteValue(
			SafeRegistryHandle key,
			string? valueName,
			Action<string>? logDiagnostic = null)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local registry mode is only supported on Windows.");
			if (key == null)
				throw new ArgumentNullException(nameof(key));

			logDiagnostic ??= _ => { };

			string name = valueName ?? string.Empty;
			logDiagnostic($"Local registry RegDeleteValue: key=0x{key.DangerousGetHandle():X}, value='{name}'.");

			var res = (Win32ErrorCode)RegDeleteValue(key, name);
			if (res != Win32ErrorCode.ERROR_SUCCESS)
				throw new Win32Exception((int)res, $"RegDeleteValue failed for value '{name}': {res}.");
		}

		internal static void SetValue(
			SafeRegistryHandle key,
			string? valueName,
			RegistryValueType valueType,
			byte[] data,
			Action<string>? logDiagnostic = null)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local registry mode is only supported on Windows.");
			if (key == null)
				throw new ArgumentNullException(nameof(key));
			if (data == null)
				throw new ArgumentNullException(nameof(data));

			logDiagnostic ??= _ => { };

			string name = valueName ?? string.Empty;
			logDiagnostic($"Local registry RegSetValueEx: key=0x{key.DangerousGetHandle():X}, value='{name}', type={(uint)valueType}, bytes={data.Length}.");

			var res = (Win32ErrorCode)RegSetValueEx(key, name, 0, (uint)valueType, data, (uint)data.Length);
			if (res != Win32ErrorCode.ERROR_SUCCESS)
				throw new Win32Exception((int)res, $"RegSetValueEx failed for value '{name}': {res}.");
		}

		internal static byte[] QuerySecurity(
			SafeRegistryHandle key,
			SecurityInfo info,
			Action<string>? logDiagnostic = null,
			Action<string>? logWarning = null)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local registry mode is only supported on Windows.");
			if (key == null)
				throw new ArgumentNullException(nameof(key));
			if (info == SecurityInfo.None)
				throw new ArgumentException("Security info must include at least one flag.", nameof(info));

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			if (SecurityInfoRequestsSacl(info))
			{
				EnsureSeSecurityPrivilegeEnabled(
					operation: "query SACL sections",
					logDiagnostic,
					logWarning);
			}

			uint bytesNeeded = 0;
			var res = (Win32ErrorCode)RegGetKeySecurity(key, (uint)info, null, ref bytesNeeded);
			if (res == Win32ErrorCode.ERROR_SUCCESS)
				return Array.Empty<byte>();

			if (res is not Win32ErrorCode.ERROR_INSUFFICIENT_BUFFER and not Win32ErrorCode.ERROR_MORE_DATA)
				throw new Win32Exception((int)res, $"RegGetKeySecurity failed: {res}.");

			if (bytesNeeded == 0)
				return Array.Empty<byte>();

			var buffer = new byte[bytesNeeded];
			var outLen = bytesNeeded;
			var res2 = (Win32ErrorCode)RegGetKeySecurity(key, (uint)info, buffer, ref outLen);
			if (res2 != Win32ErrorCode.ERROR_SUCCESS)
				throw new Win32Exception((int)res2, $"RegGetKeySecurity failed: {res2}.");

			if (outLen > 0 && outLen < buffer.Length)
				Array.Resize(ref buffer, (int)outLen);

			return buffer;
		}

		internal static void SetSecurity(
			SafeRegistryHandle key,
			SecurityInfo info,
			byte[] securityDescriptor,
			Action<string>? logDiagnostic = null,
			Action<string>? logWarning = null)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local registry mode is only supported on Windows.");
			if (key == null)
				throw new ArgumentNullException(nameof(key));
			if (info == SecurityInfo.None)
				throw new ArgumentException("Security info must include at least one flag.", nameof(info));
			if (securityDescriptor == null || securityDescriptor.Length == 0)
				throw new ArgumentException("Security descriptor must be provided.", nameof(securityDescriptor));

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			if (SecurityInfoRequestsSacl(info))
			{
				EnsureSeSecurityPrivilegeEnabled(
					operation: "set SACL sections",
					logDiagnostic,
					logWarning);
			}

			logDiagnostic($"Local registry RegSetKeySecurity: key=0x{key.DangerousGetHandle():X}, info=0x{(uint)info:X8}, bytes={securityDescriptor.Length}.");

			var res = (Win32ErrorCode)RegSetKeySecurity(key, (uint)info, securityDescriptor);

			// Match Titanis.Msrpc.Msrrp.RegistryKey.SetSecurity behavior: retry with BACKUP_SECURITY_INFORMATION.
			if (res == Win32ErrorCode.ERROR_ACCESS_DENIED && !info.HasFlag(SecurityInfo.Backup))
			{
				var backupInfo = info | SecurityInfo.Backup;
				logDiagnostic($"Local registry: access denied; retrying RegSetKeySecurity with info=0x{(uint)backupInfo:X8}.");

				LocalTokenPrivileges.EnsureBackupRestorePrivilegesEnabled(
					includeSecurityPrivilege: SecurityInfoRequestsSacl(info),
					logDiagnostic,
					logWarning);

				res = (Win32ErrorCode)RegSetKeySecurity(key, (uint)backupInfo, securityDescriptor);
			}

			if (res != Win32ErrorCode.ERROR_SUCCESS)
				throw new Win32Exception((int)res, $"RegSetKeySecurity failed: {res}.");
		}

		private static bool SecurityInfoRequestsSacl(SecurityInfo info)
			=> info.HasFlag(SecurityInfo.Sacl) || info.HasFlag(SecurityInfo.ProtectedSacl) || info.HasFlag(SecurityInfo.UnprotectedSacl);

		private static bool RegistryAccessRequestsSystemSecurity(RegistryAccessRights access)
			=> (access & AccessSystemSecurity) != 0;

		private static void EnsureSeSecurityPrivilegeEnabled(
			string operation,
			Action<string> logDiagnostic,
			Action<string> logWarning)
		{
			_ = logWarning;

			// SACL operations only depend on SeSecurityPrivilege. Suppress backup/restore warning noise
			// from the shared helper so callers get a single clear privilege error message.
			var result = LocalTokenPrivileges.EnsureBackupRestorePrivilegesEnabled(
				includeSecurityPrivilege: true,
				logDiagnostic,
				_ => { });

			LocalPrivilegeStatus? seSecurityPrivilege = null;
			foreach (var status in result.Privileges)
			{
				if (string.Equals(status.Name, "SeSecurityPrivilege", StringComparison.OrdinalIgnoreCase))
				{
					seSecurityPrivilege = status;
					break;
				}
			}

			if (seSecurityPrivilege?.State == LocalPrivilegeState.Enabled)
				return;

			var state = seSecurityPrivilege?.State.ToString() ?? LocalPrivilegeState.Unknown.ToString();
			var errorText = seSecurityPrivilege?.LastWin32Error is int err
				? $" Last error: {FormatWin32Error(err)}."
				: string.Empty;

			throw new UnauthorizedAccessException(
				$"Local registry {operation} requires SeSecurityPrivilege, but it is not enabled for the current token (state: {state}).{errorText}");
		}

		private static string FormatWin32Error(int error)
		{
			try
			{
				return $"{new Win32Exception(error).Message} (0x{error:X8})";
			}
			catch
			{
				return $"Win32 error 0x{error:X8}";
			}
		}

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		private static extern int RegOpenKeyEx(
			nint hKey,
			string? lpSubKey,
			uint ulOptions,
			uint samDesired,
			out SafeRegistryHandle phkResult);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		private static extern int RegCreateKeyEx(
			nint hKey,
			string lpSubKey,
			uint Reserved,
			string? lpClass,
			uint dwOptions,
			uint samDesired,
			IntPtr lpSecurityAttributes,
			out SafeRegistryHandle phkResult,
			out uint lpdwDisposition);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		private static extern int RegDeleteKeyEx(
			SafeRegistryHandle hKey,
			string lpSubKey,
			uint samDesired,
			uint Reserved);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		private static extern int RegDeleteValue(
			SafeRegistryHandle hKey,
			string lpValueName);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		private static extern int RegSetValueEx(
			SafeRegistryHandle hKey,
			string lpValueName,
			int Reserved,
			uint dwType,
			byte[] lpData,
			uint cbData);

		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern int RegGetKeySecurity(
			SafeRegistryHandle hKey,
			uint SecurityInformation,
			byte[]? pSecurityDescriptor,
			ref uint lpcbSecurityDescriptor);

		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern int RegSetKeySecurity(
			SafeRegistryHandle hKey,
			uint SecurityInformation,
			byte[] pSecurityDescriptor);
	}
}
