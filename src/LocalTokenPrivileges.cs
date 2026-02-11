using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal enum LocalPrivilegeState
	{
		Unknown = 0,
		NotPresent = 1,
		Disabled = 2,
		Enabled = 3,
	}

	internal sealed record LocalPrivilegeStatus(string Name)
	{
		public LocalPrivilegeState State { get; internal set; } = LocalPrivilegeState.Unknown;
		public bool Changed { get; internal set; }
		public int? LastWin32Error { get; internal set; }
	}

	internal sealed record LocalPrivilegeCheckResult
	{
		public IReadOnlyList<LocalPrivilegeStatus> Privileges { get; init; } = Array.Empty<LocalPrivilegeStatus>();

		public bool BackupAndRestoreEnabled =>
			this.Privileges.Count >= 2 &&
			this.Privileges[0].State == LocalPrivilegeState.Enabled &&
			this.Privileges[1].State == LocalPrivilegeState.Enabled;
	}

	internal static class LocalTokenPrivileges
	{
		private const string SeBackupPrivilege = "SeBackupPrivilege";
		private const string SeRestorePrivilege = "SeRestorePrivilege";
		private const string SeSecurityPrivilege = "SeSecurityPrivilege";

		private const int ErrorInsufficientBuffer = 122;
		private const int ErrorNotAllAssigned = 1300;

		private const uint SePrivilegeEnabled = 0x00000002;

		internal static LocalPrivilegeCheckResult EnsureBackupRestorePrivilegesEnabled(
			bool includeSecurityPrivilege,
			Action<string>? logDiagnostic = null,
			Action<string>? logWarning = null)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local privilege checks are only supported on Windows.");

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query | TokenAccessLevels.AdjustPrivileges);
			var token = identity.AccessToken;

			var privilegeNames = includeSecurityPrivilege
				? new[] { SeBackupPrivilege, SeRestorePrivilege, SeSecurityPrivilege }
				: new[] { SeBackupPrivilege, SeRestorePrivilege };

			var statuses = new List<LocalPrivilegeStatus>(privilegeNames.Length);
			var luidByName = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);

			Dictionary<ulong, uint>? initialAttrs = TryQueryTokenPrivileges(token, logDiagnostic);

			foreach (var name in privilegeNames)
			{
				var status = new LocalPrivilegeStatus(name);
				statuses.Add(status);

				if (!TryLookupPrivilegeValue(name, out var luid, out var lookupError))
				{
					status.LastWin32Error = lookupError;
					logWarning($"Local token: LookupPrivilegeValue({name}) failed: {FormatWin32Error(lookupError)}.");
					continue;
				}

				var luidKey = luid.ToUInt64();
				luidByName[name] = luidKey;

				if (initialAttrs != null)
				{
					if (initialAttrs.TryGetValue(luidKey, out var attrs))
						status.State = (attrs & SePrivilegeEnabled) != 0 ? LocalPrivilegeState.Enabled : LocalPrivilegeState.Disabled;
					else
						status.State = LocalPrivilegeState.NotPresent;
				}

				if (status.State == LocalPrivilegeState.Enabled)
					continue;

				// AdjustTokenPrivileges returns true even when privileges are not held, in which case
				// GetLastError() is set to ERROR_NOT_ALL_ASSIGNED. Clear last error first to avoid stale values.
				SetLastError(0);

				var tp = new TokenPrivileges
				{
					PrivilegeCount = 1,
					Privileges = new LuidAndAttributes { Luid = luid, Attributes = SePrivilegeEnabled }
				};

				if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
				{
					int err = Marshal.GetLastWin32Error();
					status.LastWin32Error = err;
					logWarning($"Local token: AdjustTokenPrivileges({name}) failed: {FormatWin32Error(err)}.");
					continue;
				}

				int adjustErr = Marshal.GetLastWin32Error();
				if (adjustErr == ErrorNotAllAssigned)
				{
					status.State = LocalPrivilegeState.NotPresent;
					status.LastWin32Error = adjustErr;
					logWarning($"Local token: {name} is not assigned to this token ({FormatWin32Error(adjustErr)}).");
					continue;
				}

				status.Changed = true;
				status.State = LocalPrivilegeState.Enabled;
			}

			// Re-query to confirm final state when possible.
			var finalAttrs = TryQueryTokenPrivileges(token, logDiagnostic);
			if (finalAttrs != null)
			{
				foreach (var status in statuses)
				{
					if (!luidByName.TryGetValue(status.Name, out var key))
						continue;

					if (finalAttrs.TryGetValue(key, out var attrs))
						status.State = (attrs & SePrivilegeEnabled) != 0 ? LocalPrivilegeState.Enabled : LocalPrivilegeState.Disabled;
					else
						status.State = LocalPrivilegeState.NotPresent;
				}
			}

			return new LocalPrivilegeCheckResult { Privileges = statuses };
		}

		private static Dictionary<ulong, uint>? TryQueryTokenPrivileges(SafeAccessTokenHandle token, Action<string> logDiagnostic)
		{
			const TokenInformationClass infoClass = TokenInformationClass.TokenPrivileges;

			if (!GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out var bytesNeeded))
			{
				int err = Marshal.GetLastWin32Error();
				if (err != ErrorInsufficientBuffer)
				{
					logDiagnostic($"Local token: GetTokenInformation(TokenPrivileges) size query failed: {FormatWin32Error(err)}.");
					return null;
				}
			}

			if (bytesNeeded <= 0)
				return null;

			var buffer = Marshal.AllocHGlobal(bytesNeeded);
			try
			{
				if (!GetTokenInformation(token, infoClass, buffer, bytesNeeded, out bytesNeeded))
				{
					int err = Marshal.GetLastWin32Error();
					logDiagnostic($"Local token: GetTokenInformation(TokenPrivileges) failed: {FormatWin32Error(err)}.");
					return null;
				}

				var count = (uint)Marshal.ReadInt32(buffer);
				var result = new Dictionary<ulong, uint>((int)count);

				var entryPtr = IntPtr.Add(buffer, sizeof(uint));
				var entrySize = Marshal.SizeOf<LuidAndAttributes>();

				for (uint i = 0; i < count; i++)
				{
					var entry = Marshal.PtrToStructure<LuidAndAttributes>(entryPtr);
					result[entry.Luid.ToUInt64()] = entry.Attributes;
					entryPtr = IntPtr.Add(entryPtr, entrySize);
				}

				return result;
			}
			finally
			{
				Marshal.FreeHGlobal(buffer);
			}
		}

		private static bool TryLookupPrivilegeValue(string privilegeName, out Luid luid, out int win32Error)
		{
			luid = default;
			win32Error = 0;

			if (string.IsNullOrWhiteSpace(privilegeName))
				throw new ArgumentException("Privilege name cannot be null or empty.", nameof(privilegeName));

			if (LookupPrivilegeValue(null, privilegeName, out luid))
				return true;

			win32Error = Marshal.GetLastWin32Error();
			return false;
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

		[StructLayout(LayoutKind.Sequential)]
		private struct Luid
		{
			public uint LowPart;
			public int HighPart;

			public ulong ToUInt64()
			{
				return ((ulong)(uint)HighPart << 32) | LowPart;
			}
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct LuidAndAttributes
		{
			public Luid Luid;
			public uint Attributes;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct TokenPrivileges
		{
			public uint PrivilegeCount;
			public LuidAndAttributes Privileges;
		}

		private enum TokenInformationClass
		{
			TokenPrivileges = 3,
		}

		[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out Luid lpLuid);

		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern bool AdjustTokenPrivileges(
			SafeAccessTokenHandle tokenHandle,
			bool disableAllPrivileges,
			ref TokenPrivileges newState,
			int bufferLength,
			IntPtr previousState,
			IntPtr returnLength);

		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern bool GetTokenInformation(
			SafeAccessTokenHandle tokenHandle,
			TokenInformationClass tokenInformationClass,
			IntPtr tokenInformation,
			int tokenInformationLength,
			out int returnLength);

		[DllImport("kernel32.dll")]
		private static extern void SetLastError(int dwErrCode);
	}
}

