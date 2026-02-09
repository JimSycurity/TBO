using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using Titanis.Net;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class LocalNtfsSecurityDescriptor
	{
		private const int DefaultInitialBufferSize = 8192;

		internal static SecurityDescriptor Read(
			UncPath uncPath,
			DateTime? timeWarpToken,
			SecurityInfo securityInfo,
			Action<string>? logDiagnostic,
			Action<string>? logWarning,
			CancellationToken cancellationToken)
		{
			return Read(
				uncPath,
				timeWarpToken,
				securityInfo,
				DefaultInitialBufferSize,
				out _,
				logDiagnostic,
				logWarning,
				cancellationToken);
		}

		internal static SecurityDescriptor Read(
			UncPath uncPath,
			DateTime? timeWarpToken,
			SecurityInfo securityInfo,
			int initialBufferSize,
			out bool isDirectory,
			Action<string>? logDiagnostic,
			Action<string>? logWarning,
			CancellationToken cancellationToken)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local NTFS mode is only supported on Windows.");
			if (uncPath is null)
				throw new ArgumentNullException(nameof(uncPath));
			if (!LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
				throw new NotSupportedException($"UNC path '{uncPath}' is not a supported local NTFS path.");
			if (securityInfo == SecurityInfo.None)
				throw new ArgumentException("SecurityInfo must include at least one flag.", nameof(securityInfo));

			isDirectory = false;
			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			var localPath = LocalNtfsUncPathMapper.MapToLocalPath(uncPath, timeWarpToken, logDiagnostic, logWarning);

			// Reading a file object's DACL/owner/group requires READ_CONTROL; reading SACL additionally requires
			// ACCESS_SYSTEM_SECURITY and SeSecurityPrivilege. LocalNtfsCreateFile enables SeBackup/SeRestore and,
			// when requested, SeSecurityPrivilege in the current process token.
			var desiredAccess = LocalNtfsFileAccess.ReadControl;
			var includeSecurityPrivilege = false;
			if (securityInfo.HasFlag(SecurityInfo.Sacl)
				|| securityInfo.HasFlag(SecurityInfo.ProtectedSacl)
				|| securityInfo.HasFlag(SecurityInfo.UnprotectedSacl))
			{
				desiredAccess |= LocalNtfsFileAccess.AccessSystemSecurity;
				includeSecurityPrivilege = true;
			}

			using var handle = LocalNtfsCreateFile.OpenFileHandle(
				localPath,
				desiredAccess,
				System.IO.FileMode.Open,
				includeSecurityPrivilege: includeSecurityPrivilege,
				logDiagnostic: logDiagnostic,
				logWarning: logWarning);

			// Determine object type for provider interop (FileSecurity vs DirectorySecurity).
			if (!GetFileInformationByHandle(handle, out var fileInfo))
				throw new Win32Exception(Marshal.GetLastWin32Error(), $"GetFileInformationByHandle failed for '{localPath}'.");

			isDirectory = 0 != (fileInfo.dwFileAttributes & FileAttributeDirectory);

			var bufferSize = Math.Max(initialBufferSize, 256);
			var buffer = new byte[bufferSize];

			while (true)
			{
				cancellationToken.ThrowIfCancellationRequested();

				if (GetKernelObjectSecurity(handle, (uint)securityInfo, buffer, buffer.Length, out var bytesNeeded))
				{
					return new SecurityDescriptor(buffer.AsSpan(0, checked((int)bytesNeeded)));
				}

				int err = Marshal.GetLastWin32Error();
				if (err != ErrorInsufficientBuffer && err != ErrorMoreData)
					throw new Win32Exception(err, $"GetKernelObjectSecurity failed for '{localPath}'.");

				if (bytesNeeded <= 0 || bytesNeeded > int.MaxValue)
					throw new InvalidOperationException($"GetKernelObjectSecurity returned an invalid required length ({bytesNeeded}).");

				buffer = new byte[bytesNeeded];
			}
		}

		internal static void Write(
			UncPath uncPath,
			DateTime? timeWarpToken,
			SecurityDescriptor securityDescriptor,
			SecurityInfo securityInfo,
			Action<string>? logDiagnostic,
			Action<string>? logWarning,
			CancellationToken cancellationToken)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local NTFS mode is only supported on Windows.");
			if (uncPath is null)
				throw new ArgumentNullException(nameof(uncPath));
			if (securityDescriptor is null)
				throw new ArgumentNullException(nameof(securityDescriptor));
			if (!LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
				throw new NotSupportedException($"UNC path '{uncPath}' is not a supported local NTFS path.");
			if (securityInfo == SecurityInfo.None)
				throw new ArgumentException("SecurityInfo must include at least one flag.", nameof(securityInfo));

			if (timeWarpToken.HasValue || HasTimeWarpToken(uncPath))
				throw new NotSupportedException("Snapshot paths are read-only.");

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			var localPath = LocalNtfsUncPathMapper.MapToLocalPath(uncPath, timeWarpToken, logDiagnostic, logWarning);

			var desiredAccess = LocalNtfsFileAccess.ReadControl;

			// Setting DACL-related sections requires WRITE_DAC.
			if (securityInfo.HasFlag(SecurityInfo.Dacl)
				|| securityInfo.HasFlag(SecurityInfo.ProtectedDacl)
				|| securityInfo.HasFlag(SecurityInfo.UnprotectedDacl))
			{
				desiredAccess |= LocalNtfsFileAccess.WriteDac;
			}

			// Setting owner/group requires WRITE_OWNER.
			if (securityInfo.HasFlag(SecurityInfo.Owner) || securityInfo.HasFlag(SecurityInfo.Group))
				desiredAccess |= LocalNtfsFileAccess.WriteOwner;

			var includeSecurityPrivilege = false;

			// Setting SACL-related sections requires ACCESS_SYSTEM_SECURITY and SeSecurityPrivilege.
			if (securityInfo.HasFlag(SecurityInfo.Sacl)
				|| securityInfo.HasFlag(SecurityInfo.ProtectedSacl)
				|| securityInfo.HasFlag(SecurityInfo.UnprotectedSacl))
			{
				desiredAccess |= LocalNtfsFileAccess.AccessSystemSecurity;
				includeSecurityPrivilege = true;
			}

			using var handle = LocalNtfsCreateFile.OpenFileHandle(
				localPath,
				desiredAccess,
				System.IO.FileMode.Open,
				includeSecurityPrivilege: includeSecurityPrivilege,
				logDiagnostic: logDiagnostic,
				logWarning: logWarning);

			var sdBytes = securityDescriptor.ToByteArray();
			var pSd = Marshal.AllocHGlobal(sdBytes.Length);
			try
			{
				Marshal.Copy(sdBytes, 0, pSd, sdBytes.Length);

				cancellationToken.ThrowIfCancellationRequested();

				if (!SetKernelObjectSecurity(handle, (uint)securityInfo, pSd))
					throw new Win32Exception(Marshal.GetLastWin32Error(), $"SetKernelObjectSecurity failed for '{localPath}'.");
			}
			finally
			{
				Marshal.FreeHGlobal(pSd);
			}
		}

		private const int ErrorInsufficientBuffer = 122;
		private const int ErrorMoreData = 234;
		private const uint FileAttributeDirectory = 0x00000010;

		[StructLayout(LayoutKind.Sequential)]
		private struct ByHandleFileInformation
		{
			public uint dwFileAttributes;
			public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
			public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
			public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
			public uint dwVolumeSerialNumber;
			public uint nFileSizeHigh;
			public uint nFileSizeLow;
			public uint nNumberOfLinks;
			public uint nFileIndexHigh;
			public uint nFileIndexLow;
		}

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool GetFileInformationByHandle(
			SafeFileHandle hFile,
			out ByHandleFileInformation lpFileInformation);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool GetKernelObjectSecurity(
			SafeHandle handle,
			uint securityInformation,
			[Out] byte[] pSecurityDescriptor,
			int nLength,
			out int lpnLengthNeeded);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool SetKernelObjectSecurity(
			SafeHandle handle,
			uint securityInformation,
			IntPtr pSecurityDescriptor);

		private static bool HasTimeWarpToken(UncPath uncPath)
		{
			var relativePath = uncPath.ShareRelativePath;
			if (string.IsNullOrEmpty(relativePath))
				return false;

			var separatorIndex = relativePath.IndexOf('\\');
			var firstSegment = separatorIndex >= 0 ? relativePath.Substring(0, separatorIndex) : relativePath;
			if (!firstSegment.StartsWith("@GMT-", StringComparison.OrdinalIgnoreCase))
				return false;

			return true;
		}
	}
}
