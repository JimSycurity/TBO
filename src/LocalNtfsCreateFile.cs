using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Flags]
	internal enum LocalNtfsFileAccess : uint
	{
		None = 0,

		// "Specific rights" for file objects. Note that some bits map differently for directories
		// (ex: 0x0001 is FILE_READ_DATA for files and FILE_LIST_DIRECTORY for directories).
		ReadDataOrListDirectory = 0x00000001,
		WriteDataOrAddFile = 0x00000002,
		AppendDataOrAddSubdirectory = 0x00000004,
		ReadExtendedAttributes = 0x00000008,
		WriteExtendedAttributes = 0x00000010,
		ExecuteOrTraverse = 0x00000020,
		DeleteChild = 0x00000040,
		ReadAttributes = 0x00000080,
		WriteAttributes = 0x00000100,

		// Standard rights.
		Delete = 0x00010000,
		ReadControl = 0x00020000,
		WriteDac = 0x00040000,
		WriteOwner = 0x00080000,
		Synchronize = 0x00100000,

		// Required for SACL access (also requires SeSecurityPrivilege).
		AccessSystemSecurity = 0x01000000,

		// Generic rights (allowed, but callers should prefer explicit rights instead of GenericAll).
		GenericAll = 0x10000000,
		GenericExecute = 0x20000000,
		GenericWrite = 0x40000000,
		GenericRead = 0x80000000,
	}

	[Flags]
	internal enum LocalNtfsOpenFlags : uint
	{
		None = 0,
		OpenReparsePoint = 0x00200000, // FILE_FLAG_OPEN_REPARSE_POINT
	}

	internal static class LocalNtfsCreateFile
	{
		private const uint FileFlagBackupSemantics = 0x02000000; // FILE_FLAG_BACKUP_SEMANTICS
		private const uint FileAttributeNormal = 0x00000080; // FILE_ATTRIBUTE_NORMAL

		internal static SafeFileHandle OpenFileHandle(
			string path,
			LocalNtfsFileAccess desiredAccess,
			FileMode mode,
			FileShare share = FileShare.ReadWrite | FileShare.Delete,
			LocalNtfsOpenFlags flags = LocalNtfsOpenFlags.None,
			bool includeSecurityPrivilege = false,
			Action<string>? logDiagnostic = null,
			Action<string>? logWarning = null)
		{
			return OpenHandleCore(
				path,
				isDirectory: false,
				desiredAccess,
				mode,
				share,
				flags,
				includeSecurityPrivilege,
				logDiagnostic,
				logWarning);
		}

		internal static SafeFileHandle OpenDirectoryHandle(
			string path,
			LocalNtfsFileAccess desiredAccess,
			FileShare share = FileShare.ReadWrite | FileShare.Delete,
			LocalNtfsOpenFlags flags = LocalNtfsOpenFlags.None,
			bool includeSecurityPrivilege = false,
			Action<string>? logDiagnostic = null,
			Action<string>? logWarning = null)
		{
			return OpenHandleCore(
				path,
				isDirectory: true,
				desiredAccess,
				FileMode.Open,
				share,
				flags,
				includeSecurityPrivilege,
				logDiagnostic,
				logWarning);
		}

		internal static FileStream OpenFileStream(
			string path,
			LocalNtfsFileAccess desiredAccess,
			FileMode mode,
			FileAccess streamAccess,
			FileShare share = FileShare.ReadWrite | FileShare.Delete,
			LocalNtfsOpenFlags flags = LocalNtfsOpenFlags.None,
			bool includeSecurityPrivilege = false,
			Action<string>? logDiagnostic = null,
			Action<string>? logWarning = null,
			int bufferSize = 4096,
			bool isAsync = false)
		{
			var handle = OpenFileHandle(path, desiredAccess, mode, share, flags, includeSecurityPrivilege, logDiagnostic, logWarning);
			try
			{
				return new FileStream(handle, streamAccess, bufferSize, isAsync);
			}
			catch
			{
				handle.Dispose();
				throw;
			}
		}

		private static SafeFileHandle OpenHandleCore(
			string path,
			bool isDirectory,
			LocalNtfsFileAccess desiredAccess,
			FileMode mode,
			FileShare share,
			LocalNtfsOpenFlags flags,
			bool includeSecurityPrivilege,
			Action<string>? logDiagnostic,
			Action<string>? logWarning)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local NTFS mode is only supported on Windows.");
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path cannot be null or empty.", nameof(path));

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			// Local mode relies on backup/restore privileges being enabled. This enables them if present.
			// If a privilege is not assigned, we still attempt the open; the open may succeed if normal
			// access checks allow it (or fail with a standard Win32 error).
			LocalTokenPrivileges.EnsureBackupRestorePrivilegesEnabled(
				includeSecurityPrivilege,
				logDiagnostic,
				logWarning);

			if (isDirectory && mode != FileMode.Open)
				throw new ArgumentException("Directories can only be opened with FileMode.Open.", nameof(mode));

			var normalizedPath = NormalizeWin32Path(path);
			var creationDisposition = MapFileModeToCreationDisposition(mode);

			// Backup semantics are required to open directories via CreateFileW and are also required
			// to get the OS to honor SeBackupPrivilege/SeRestorePrivilege bypass behavior.
			uint flagsAndAttributes = FileFlagBackupSemantics;
			flagsAndAttributes |= (uint)flags;
			if (!isDirectory)
				flagsAndAttributes |= FileAttributeNormal;

			logDiagnostic($"Local NTFS CreateFileW: path='{path}', access=0x{(uint)desiredAccess:X8}, share=0x{(uint)share:X8}, disposition={creationDisposition}, flags=0x{flagsAndAttributes:X8}, directory={isDirectory}.");

			var handle = CreateFileW(
				normalizedPath,
				(uint)desiredAccess,
				(uint)share,
				IntPtr.Zero,
				creationDisposition,
				flagsAndAttributes,
				IntPtr.Zero);

			if (!handle.IsInvalid)
				return handle;

			int err = Marshal.GetLastWin32Error();
			handle.Dispose();
			throw new Win32Exception(err, $"CreateFileW failed for '{path}': {FormatWin32Error(err)}.");
		}

		private static string NormalizeWin32Path(string path)
		{
			// Normalize to a full path and apply extended-length prefix to avoid MAX_PATH issues.
			string fullPath = Path.GetFullPath(path);

			if (fullPath.StartsWith(@"\\?\") || fullPath.StartsWith(@"\\.\"))
				return fullPath;

			if (fullPath.StartsWith(@"\\"))
			{
				// UNC path: \\server\share\... -> \\?\UNC\server\share\...
				return @"\\?\UNC\" + fullPath.Substring(2);
			}

			return @"\\?\" + fullPath;
		}

		private static uint MapFileModeToCreationDisposition(FileMode mode)
		{
			return mode switch
			{
				FileMode.CreateNew => 1,     // CREATE_NEW
				FileMode.Create => 2,        // CREATE_ALWAYS
				FileMode.Open => 3,          // OPEN_EXISTING
				FileMode.OpenOrCreate => 4,  // OPEN_ALWAYS
				FileMode.Truncate => 5,      // TRUNCATE_EXISTING
				FileMode.Append => 4,        // OPEN_ALWAYS (caller is responsible for seek-to-end semantics)
				_ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unsupported FileMode."),
			};
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

		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		private static extern SafeFileHandle CreateFileW(
			string lpFileName,
			uint dwDesiredAccess,
			uint dwShareMode,
			IntPtr lpSecurityAttributes,
			uint dwCreationDisposition,
			uint dwFlagsAndAttributes,
			IntPtr hTemplateFile);
	}
}

