using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using Titanis.Smb2;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class LocalNtfsStreams
	{
		private const int ErrorInsufficientBuffer = 122;
		private const int ErrorMoreData = 234;
		private const int InitialBufferSize = 16 * 1024;
		private const int MaxBufferSize = 4 * 1024 * 1024;
		private const int StreamInfoHeaderSize = 24;

		internal static FileStreamInfo[] ReadStreams(
			string path,
			Action<string>? logDiagnostic,
			Action<string>? logWarning,
			CancellationToken cancellationToken)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Local NTFS mode is only supported on Windows.");
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			// Querying stream info requires FILE_READ_ATTRIBUTES. Open with backup semantics and permissive sharing
			// so we behave similarly to SMB read opens.
			var desiredAccess = LocalNtfsFileAccess.ReadAttributes | LocalNtfsFileAccess.Synchronize;
			using SafeFileHandle handle = LocalNtfsCreateFile.OpenFileHandle(
				path,
				desiredAccess,
				FileMode.Open,
				share: FileShare.ReadWrite | FileShare.Delete,
				includeSecurityPrivilege: false,
				logDiagnostic: logDiagnostic,
				logWarning: logWarning);

			var bufferSize = InitialBufferSize;
			while (true)
			{
				cancellationToken.ThrowIfCancellationRequested();

				IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
				try
				{
					if (GetFileInformationByHandleEx(handle, FileInfoByHandleClass.FileStreamInfo, buffer, (uint)bufferSize))
					{
						return ParseStreamInfoBuffer(buffer, bufferSize);
					}

					int err = Marshal.GetLastWin32Error();
					if (err == ErrorInsufficientBuffer || err == ErrorMoreData)
					{
						// Buffer was too small; retry with a larger allocation.
						if (bufferSize >= MaxBufferSize)
							throw new InvalidOperationException($"File stream info is unexpectedly large (> {MaxBufferSize} bytes) for '{path}'.");

						bufferSize = Math.Min(MaxBufferSize, checked(bufferSize * 2));
						continue;
					}

					throw new Win32Exception(err, $"GetFileInformationByHandleEx(FileStreamInfo) failed for '{path}'.");
				}
				finally
				{
					Marshal.FreeHGlobal(buffer);
				}
			}
		}

		private static FileStreamInfo[] ParseStreamInfoBuffer(IntPtr buffer, int bufferSize)
		{
			var streams = new List<FileStreamInfo>();

			var offset = 0;
			while (true)
			{
				if (offset < 0 || offset + StreamInfoHeaderSize > bufferSize)
					throw new InvalidOperationException("GetFileInformationByHandleEx returned an invalid FileStreamInfo buffer.");

				var pEntry = IntPtr.Add(buffer, offset);

				uint nextEntryOffset = unchecked((uint)Marshal.ReadInt32(pEntry, 0));
				int streamNameLength = Marshal.ReadInt32(pEntry, 4);
				long streamSize = Marshal.ReadInt64(pEntry, 8);
				long streamAllocationSize = Marshal.ReadInt64(pEntry, 16);

				if (streamNameLength < 0 || (streamNameLength % 2) != 0)
					throw new InvalidOperationException("GetFileInformationByHandleEx returned an invalid stream name length.");
				if (offset + StreamInfoHeaderSize + streamNameLength > bufferSize)
					throw new InvalidOperationException("GetFileInformationByHandleEx returned a truncated stream entry.");

				string name = string.Empty;
				if (streamNameLength > 0)
				{
					var pName = IntPtr.Add(pEntry, StreamInfoHeaderSize);
					name = Marshal.PtrToStringUni(pName, streamNameLength / 2) ?? string.Empty;
				}

				streams.Add(new FileStreamInfo(name, streamSize, streamAllocationSize));

				if (nextEntryOffset == 0)
					break;

				if (nextEntryOffset < StreamInfoHeaderSize)
					throw new InvalidOperationException("GetFileInformationByHandleEx returned an invalid next-entry offset.");

				offset = checked(offset + (int)nextEntryOffset);
				if (offset > bufferSize)
					throw new InvalidOperationException("GetFileInformationByHandleEx returned an out-of-range next-entry offset.");
			}

			return streams.ToArray();
		}

		private enum FileInfoByHandleClass
		{
			FileStreamInfo = 7,
		}

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool GetFileInformationByHandleEx(
			SafeFileHandle hFile,
			FileInfoByHandleClass fileInformationClass,
			IntPtr lpFileInformation,
			uint dwBufferSize);
	}
}

