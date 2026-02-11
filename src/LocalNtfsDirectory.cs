using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class LocalNtfsDirectory : ISmbDirectory
	{
		private readonly string _path;
		private readonly SafeFileHandle _handle;
		private readonly Action<string> _logDiagnostic;
		private readonly Action<string> _logWarning;

		internal LocalNtfsDirectory(
			string path,
			Action<string>? logDiagnostic = null,
			Action<string>? logWarning = null)
		{
			this._path = path ?? throw new ArgumentNullException(nameof(path));
			this._logDiagnostic = logDiagnostic ?? (_ => { });
			this._logWarning = logWarning ?? (_ => { });

			// NtQueryDirectoryFile requires a directory HANDLE opened with FILE_LIST_DIRECTORY. We open the
			// directory via CreateFileW using backup semantics, so SeBackupPrivilege bypass behavior applies.
			this._handle = LocalNtfsCreateFile.OpenDirectoryHandle(
				path,
				LocalNtfsFileAccess.ReadDataOrListDirectory | LocalNtfsFileAccess.ReadAttributes,
				includeSecurityPrivilege: false,
				logDiagnostic: this._logDiagnostic,
				logWarning: this._logWarning);
		}

		public IReadOnlyList<Smb2DirEntry> QueryEntries(
			string pattern,
			Smb2Directory.Smb2DirQueryOptions options,
			SecurityInfo securityInfo,
			int bufferSize,
			CancellationToken cancellationToken)
		{
			return LocalNtfsDirectoryEnumeration.QueryEntries(
				this._handle,
				pattern,
				options,
				bufferSize,
				cancellationToken,
				this._logDiagnostic);
		}

		public void Dispose()
		{
			this._handle.Dispose();
		}
	}

	internal static class LocalNtfsDirectoryEnumeration
	{
		private const int StatusSuccess = 0x00000000;
		private const int StatusNoMoreFiles = unchecked((int)0x80000006);
		private const int StatusBufferOverflow = unchecked((int)0x80000005);

		private const int MinQueryBufferSize = 4096;
		private const int FileFullDirectoryInformation = 2;

		internal static IReadOnlyList<Smb2DirEntry> QueryEntries(
			SafeFileHandle directoryHandle,
			string pattern,
			Smb2Directory.Smb2DirQueryOptions options,
			int bufferSize,
			CancellationToken cancellationToken,
			Action<string>? logDiagnostic = null)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local NTFS mode is only supported on Windows.");
			if (directoryHandle is null)
				throw new ArgumentNullException(nameof(directoryHandle));
			if (directoryHandle.IsInvalid)
				throw new ArgumentException("Directory handle is invalid.", nameof(directoryHandle));

			logDiagnostic ??= _ => { };

			var results = new List<Smb2DirEntry>();
			var effectivePattern = string.IsNullOrEmpty(pattern) ? "*" : pattern;

			var effectiveBufferSize = Math.Max(bufferSize, MinQueryBufferSize);
			var buffer = Marshal.AllocHGlobal(effectiveBufferSize);
			try
			{
				bool restartScan = true;
				while (true)
				{
					cancellationToken.ThrowIfCancellationRequested();

					var status = NtQueryDirectoryFile(
						directoryHandle,
						IntPtr.Zero,
						IntPtr.Zero,
						IntPtr.Zero,
						out var ioStatus,
						buffer,
						(uint)effectiveBufferSize,
						FileFullDirectoryInformation,
						false,
						IntPtr.Zero,
						restartScan);

					restartScan = false;

					if (status == StatusNoMoreFiles)
						break;

					if (status != StatusSuccess && status != StatusBufferOverflow)
						throw new NtstatusException((Ntstatus)status);

					var bytesReturned = checked((int)ioStatus.Information.ToUInt64());
					if (bytesReturned <= 0)
					{
						// Defensive: avoid infinite loops if the API reports success but returns no data.
						logDiagnostic("Local NTFS NtQueryDirectoryFile returned success with 0 bytes; stopping enumeration.");
						break;
					}

					ParseFileFullDirectoryInformation(buffer, bytesReturned, effectivePattern, options, results);
				}

				return results;
			}
			finally
			{
				Marshal.FreeHGlobal(buffer);
			}
		}

		private static void ParseFileFullDirectoryInformation(
			IntPtr buffer,
			int bytesReturned,
			string pattern,
			Smb2Directory.Smb2DirQueryOptions options,
			List<Smb2DirEntry> results)
		{
			// Avoid unsafe code by copying the returned bytes into a managed buffer.
			var bufferBytes = new byte[bytesReturned];
			Marshal.Copy(buffer, bufferBytes, 0, bytesReturned);
			var baseSpan = new ReadOnlySpan<byte>(bufferBytes);
			var offset = 0;
			while (offset < baseSpan.Length)
			{
				if (baseSpan.Length - offset < 68)
					break;

				var entrySpan = baseSpan.Slice(offset);
				var nextEntryOffset = BinaryPrimitives.ReadUInt32LittleEndian(entrySpan.Slice(0, 4));

				uint fileIndex = BinaryPrimitives.ReadUInt32LittleEndian(entrySpan.Slice(4, 4));
				long creationTime = BinaryPrimitives.ReadInt64LittleEndian(entrySpan.Slice(8, 8));
				long lastAccessTime = BinaryPrimitives.ReadInt64LittleEndian(entrySpan.Slice(16, 8));
				long lastWriteTime = BinaryPrimitives.ReadInt64LittleEndian(entrySpan.Slice(24, 8));
				long changeTime = BinaryPrimitives.ReadInt64LittleEndian(entrySpan.Slice(32, 8));
				long endOfFile = BinaryPrimitives.ReadInt64LittleEndian(entrySpan.Slice(40, 8));
				long allocationSize = BinaryPrimitives.ReadInt64LittleEndian(entrySpan.Slice(48, 8));
				uint fileAttributes = BinaryPrimitives.ReadUInt32LittleEndian(entrySpan.Slice(56, 4));
				uint fileNameLength = BinaryPrimitives.ReadUInt32LittleEndian(entrySpan.Slice(60, 4));
				uint eaSize = BinaryPrimitives.ReadUInt32LittleEndian(entrySpan.Slice(64, 4));

				var nameOffset = 68;
				if (fileNameLength > int.MaxValue || nameOffset + (int)fileNameLength > entrySpan.Length)
					break;

				var nameBytes = entrySpan.Slice(nameOffset, (int)fileNameLength);
				var name = Encoding.Unicode.GetString(nameBytes);
				if (!string.IsNullOrEmpty(name) && name is not "." and not "..")
				{
					if (MatchesPattern(name, pattern))
					{
						results.Add(new Smb2DirEntry
						{
							FileName = name,
							RelativePath = name,
							FileIndex = fileIndex,
							CreationTime = DateTime.FromFileTimeUtc(creationTime),
							LastAccessTime = DateTime.FromFileTimeUtc(lastAccessTime),
							LastWriteTime = DateTime.FromFileTimeUtc(lastWriteTime),
							LastChangeTime = DateTime.FromFileTimeUtc(changeTime),
							Size = (ulong)Math.Max(0, endOfFile),
							SizeOnDisk = (ulong)Math.Max(0, allocationSize),
							FileAttributes = (Titanis.Winterop.FileAttributes)fileAttributes,
							EaSize = eaSize,
						});
					}
				}

				if (nextEntryOffset == 0)
					break;

				offset = checked(offset + (int)nextEntryOffset);
			}
		}

		private static bool MatchesPattern(string name, string pattern)
		{
			if (string.IsNullOrEmpty(pattern) || pattern == "*")
				return true;
			if (!pattern.Contains('*') && !pattern.Contains('?'))
				return string.Equals(name, pattern, StringComparison.OrdinalIgnoreCase);

			var escaped = System.Text.RegularExpressions.Regex.Escape(pattern);
			escaped = escaped.Replace("\\*", ".*").Replace("\\?", ".");
			var regex = new System.Text.RegularExpressions.Regex("^" + escaped + "$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
			return regex.IsMatch(name);
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct IoStatusBlock
		{
			public IntPtr StatusPointer;
			public UIntPtr Information;
		}

		[DllImport("ntdll.dll")]
		private static extern int NtQueryDirectoryFile(
			SafeFileHandle fileHandle,
			IntPtr eventHandle,
			IntPtr apcRoutine,
			IntPtr apcContext,
			out IoStatusBlock ioStatusBlock,
			IntPtr fileInformation,
			uint length,
			int fileInformationClass,
			[MarshalAs(UnmanagedType.U1)] bool returnSingleEntry,
			IntPtr fileName,
			[MarshalAs(UnmanagedType.U1)] bool restartScan);
	}
}
