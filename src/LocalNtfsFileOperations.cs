using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class LocalNtfsFileOperations
	{
		private const int ErrorFileExists = 80;
		private const int ErrorAlreadyExists = 183;

		internal static void CreateEmptyFile(
			string localPath,
			Action<string>? logDiagnostic,
			Action<string>? logWarning,
			CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();

			if (string.IsNullOrWhiteSpace(localPath))
				throw new ArgumentException("Path cannot be null or empty.", nameof(localPath));

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			// Mirror SMB create semantics: request explicit write rights (avoid GenericAll),
			// open with backup semantics, and allow other readers/writers/deleters to share.
			var desiredAccess =
				LocalNtfsFileAccess.WriteDataOrAddFile |
				LocalNtfsFileAccess.AppendDataOrAddSubdirectory |
				LocalNtfsFileAccess.WriteAttributes |
				LocalNtfsFileAccess.WriteExtendedAttributes |
				LocalNtfsFileAccess.ReadAttributes |
				LocalNtfsFileAccess.ReadExtendedAttributes |
				LocalNtfsFileAccess.Synchronize;

			logDiagnostic($"Local NTFS create file: '{localPath}'.");

			using var _ = LocalNtfsCreateFile.OpenFileHandle(
				localPath,
				desiredAccess,
				FileMode.CreateNew,
				share: FileShare.ReadWrite | FileShare.Delete,
				flags: LocalNtfsOpenFlags.None,
				includeSecurityPrivilege: false,
				logDiagnostic: logDiagnostic,
				logWarning: logWarning);
		}

		internal static void CreateDirectory(
			string localPath,
			Action<string>? logDiagnostic,
			Action<string>? logWarning,
			CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();

			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local NTFS mode is only supported on Windows.");
			if (string.IsNullOrWhiteSpace(localPath))
				throw new ArgumentException("Path cannot be null or empty.", nameof(localPath));

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			// CreateDirectoryW is path-based. We still enable backup/restore privileges to keep local-mode
			// behavior aligned (and to surface useful warnings if the token is missing privileges).
			LocalTokenPrivileges.EnsureBackupRestorePrivilegesEnabled(
				includeSecurityPrivilege: false,
				logDiagnostic: logDiagnostic,
				logWarning: logWarning);

			var normalized = NormalizeWin32Path(localPath);

			logDiagnostic($"Local NTFS CreateDirectoryW: '{localPath}'.");

			if (CreateDirectoryW(normalized, IntPtr.Zero))
				return;

			int err = Marshal.GetLastWin32Error();
			if (err == ErrorAlreadyExists || err == ErrorFileExists)
				throw new IOException($"The path '{localPath}' already exists.");

			throw new Win32Exception(err, $"CreateDirectoryW failed for '{localPath}': {FormatWin32Error(err)}.");
		}

		internal static void DeleteFile(
			string localPath,
			bool openReparsePoint,
			Action<string>? logDiagnostic,
			Action<string>? logWarning,
			CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();

			if (string.IsNullOrWhiteSpace(localPath))
				throw new ArgumentException("Path cannot be null or empty.", nameof(localPath));

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			var flags = openReparsePoint ? LocalNtfsOpenFlags.OpenReparsePoint : LocalNtfsOpenFlags.None;

			// Match SMB behavior: open the object with backup semantics and delete-on-close semantics.
			var desiredAccess = LocalNtfsFileAccess.Delete | LocalNtfsFileAccess.ReadAttributes | LocalNtfsFileAccess.Synchronize;

			using var handle = LocalNtfsCreateFile.OpenFileHandle(
				localPath,
				desiredAccess,
				FileMode.Open,
				share: FileShare.ReadWrite | FileShare.Delete,
				flags: flags,
				includeSecurityPrivilege: false,
				logDiagnostic: logDiagnostic,
				logWarning: logWarning);

			logDiagnostic($"Local NTFS delete-on-close (file): '{localPath}', reparse={openReparsePoint}.");
			MarkDeleteOnClose(handle, localPath);
		}

		internal static void DeleteDirectory(
			string localPath,
			bool openReparsePoint,
			Action<string>? logDiagnostic,
			Action<string>? logWarning,
			CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();

			if (string.IsNullOrWhiteSpace(localPath))
				throw new ArgumentException("Path cannot be null or empty.", nameof(localPath));

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			var flags = openReparsePoint ? LocalNtfsOpenFlags.OpenReparsePoint : LocalNtfsOpenFlags.None;

			var desiredAccess = LocalNtfsFileAccess.Delete | LocalNtfsFileAccess.ReadAttributes | LocalNtfsFileAccess.Synchronize;

			using var handle = LocalNtfsCreateFile.OpenDirectoryHandle(
				localPath,
				desiredAccess,
				share: FileShare.ReadWrite | FileShare.Delete,
				flags: flags,
				includeSecurityPrivilege: false,
				logDiagnostic: logDiagnostic,
				logWarning: logWarning);

			logDiagnostic($"Local NTFS delete-on-close (dir): '{localPath}', reparse={openReparsePoint}.");
			MarkDeleteOnClose(handle, localPath);
		}

		private static void MarkDeleteOnClose(SafeFileHandle handle, string localPath)
		{
			var info = new FileDispositionInfo { DeleteFile = true };
			var size = (uint)Marshal.SizeOf<FileDispositionInfo>();

			if (SetFileInformationByHandle(handle, FileInfoByHandleClass.FileDispositionInfo, ref info, size))
				return;

			int err = Marshal.GetLastWin32Error();
			throw new Win32Exception(err, $"SetFileInformationByHandle(FileDispositionInfo) failed for '{localPath}': {FormatWin32Error(err)}.");
		}

		private static string NormalizeWin32Path(string path)
		{
			// Normalize to a full path and apply extended-length prefix to avoid MAX_PATH issues.
			string fullPath = Path.GetFullPath(path);

			if (fullPath.StartsWith(@"\\?\") || fullPath.StartsWith(@"\\.\"))
				return fullPath;

			if (fullPath.StartsWith(@"\\"))
				return @"\\?\UNC\" + fullPath.Substring(2);

			return @"\\?\" + fullPath;
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

		private enum FileInfoByHandleClass : int
		{
			FileDispositionInfo = 4,
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct FileDispositionInfo
		{
			[MarshalAs(UnmanagedType.Bool)]
			public bool DeleteFile;
		}

		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool CreateDirectoryW(string lpPathName, IntPtr lpSecurityAttributes);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool SetFileInformationByHandle(
			SafeFileHandle hFile,
			FileInfoByHandleClass fileInformationClass,
			ref FileDispositionInfo lpFileInformation,
			uint dwBufferSize);
	}
}

