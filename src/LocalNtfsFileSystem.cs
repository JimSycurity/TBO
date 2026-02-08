using System;
using System.IO;
using System.Threading;
using Titanis.Net;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class LocalNtfsFileSystem : ISmbFileSystem
	{
		private readonly Action<string> _logDiagnostic;
		private readonly Action<string> _logWarning;

		internal LocalNtfsFileSystem(Action<string>? logDiagnostic = null, Action<string>? logWarning = null)
		{
			this._logDiagnostic = logDiagnostic ?? (_ => { });
			this._logWarning = logWarning ?? (_ => { });
		}

		public ISmbDirectory OpenDirectory(UncPath path, CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();

			var localPath = LocalNtfsUncPathMapper.MapToLocalPath(path);
			return new LocalNtfsDirectory(localPath, this._logDiagnostic, this._logWarning);
		}

		public ISmbFile OpenFileRead(UncPath path, CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();

			var localPath = LocalNtfsUncPathMapper.MapToLocalPath(path);
			return new LocalNtfsFile(localPath, this._logDiagnostic, this._logWarning);
		}

		private sealed class LocalNtfsFile : ISmbFile
		{
			private readonly FileStream _stream;

			public LocalNtfsFile(string path, Action<string> logDiagnostic, Action<string> logWarning)
			{
				if (string.IsNullOrWhiteSpace(path))
					throw new ArgumentException("Path cannot be null or empty.", nameof(path));

				// Mirror SMB read semantics: open with backup intent, request explicit read rights,
				// and allow other readers/writers/deleters to share the handle.
				const FileShare share = FileShare.ReadWrite | FileShare.Delete;
				const FileMode mode = FileMode.Open;
				const FileAccess streamAccess = FileAccess.Read;

				var access =
					LocalNtfsFileAccess.ReadDataOrListDirectory |
					LocalNtfsFileAccess.ReadAttributes |
					LocalNtfsFileAccess.ReadExtendedAttributes |
					LocalNtfsFileAccess.Synchronize;

				this._stream = LocalNtfsCreateFile.OpenFileStream(
					path,
					access,
					mode,
					streamAccess,
					share,
					flags: LocalNtfsOpenFlags.None,
					includeSecurityPrivilege: false,
					logDiagnostic: logDiagnostic,
					logWarning: logWarning);
			}

			public Stream OpenRead()
			{
				try
				{
					this._stream.Position = 0;
				}
				catch
				{
				}

				return this._stream;
			}

			public long Length => this._stream.Length;

			public void Dispose()
			{
				this._stream.Dispose();
			}
		}
	}

	internal sealed class HybridSmbFileSystem : ISmbFileSystem
	{
		private readonly ISmbFileSystem _remote;
		private readonly ISmbFileSystem _local;

		internal HybridSmbFileSystem(ISmbFileSystem remote, ISmbFileSystem local)
		{
			this._remote = remote ?? throw new ArgumentNullException(nameof(remote));
			this._local = local ?? throw new ArgumentNullException(nameof(local));
		}

		public ISmbDirectory OpenDirectory(UncPath path, CancellationToken cancellationToken)
		{
			if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(path))
				return this._local.OpenDirectory(path, cancellationToken);

			return this._remote.OpenDirectory(path, cancellationToken);
		}

		public ISmbFile OpenFileRead(UncPath path, CancellationToken cancellationToken)
		{
			if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(path))
				return this._local.OpenFileRead(path, cancellationToken);

			return this._remote.OpenFileRead(path, cancellationToken);
		}
	}

	internal static class LocalNtfsUncPathMapper
	{
		internal static bool IsSupportedLocalAdminShare(UncPath path)
		{
			if (path == null)
				return false;

			if (!IsLocalHost(path.ServerName))
				return false;

			return TryParseDriveShare(path.ShareName, out _);
		}

		internal static string MapToLocalPath(UncPath path)
		{
			if (path is null)
				throw new ArgumentNullException(nameof(path));

			if (!TryMapToLocalPath(path, out var localPath, out var reason))
				throw new NotSupportedException(reason ?? $"UNC path '{path}' is not a supported local NTFS path.");

			return localPath;
		}

		internal static bool TryMapToLocalPath(UncPath path, out string localPath, out string? failureReason)
		{
			localPath = string.Empty;
			failureReason = null;

			if (path is null)
			{
				failureReason = "UNC path is null.";
				return false;
			}

			if (!IsLocalHost(path.ServerName))
			{
				failureReason = $"UNC host '{path.ServerName}' is not treated as local.";
				return false;
			}

			if (!TryParseDriveShare(path.ShareName, out var driveLetter))
			{
				failureReason = $"UNC share '{path.ShareName}' is not a supported local admin share. Expected '<DriveLetter>$' (ex: 'C$').";
				return false;
			}

			var root = $"{char.ToUpperInvariant(driveLetter)}:\\";

			var relative = path.ShareRelativePath ?? string.Empty;
			relative = relative.Replace('/', '\\').TrimStart('\\');

			var combined = Path.GetFullPath(Path.Combine(root, relative));

			// Ensure the resolved path stays rooted on the requested drive.
			if (!combined.StartsWith(root, StringComparison.OrdinalIgnoreCase))
			{
				failureReason = $"UNC path '{path}' resolves outside of '{root}' and is not permitted.";
				return false;
			}

			localPath = combined;
			return true;
		}

		internal static bool IsLocalHost(string? serverName)
		{
			if (string.IsNullOrWhiteSpace(serverName))
				return false;

			var name = serverName.Trim().TrimStart('\\').TrimEnd('\\');

			// UNC IPv6 literal paths are sometimes written as \\[::1]\C$\...
			if (name.Length >= 2 && name[0] == '[' && name[name.Length - 1] == ']')
				name = name.Substring(1, name.Length - 2);

			if (name.Equals("localhost", StringComparison.OrdinalIgnoreCase))
				return true;
			if (name.Equals(".", StringComparison.OrdinalIgnoreCase))
				return true;
			if (name.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
				return true;
			if (name.Equals("::1", StringComparison.OrdinalIgnoreCase))
				return true;

			try
			{
				if (name.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase))
					return true;
			}
			catch
			{
			}

			return false;
		}

		private static bool TryParseDriveShare(string? shareName, out char driveLetter)
		{
			driveLetter = default;

			if (string.IsNullOrWhiteSpace(shareName))
				return false;

			var trimmed = shareName.Trim().Trim('\\');
			if (trimmed.Length != 2)
				return false;

			var letter = trimmed[0];
			var dollar = trimmed[1];
			if (!char.IsLetter(letter) || dollar != '$')
				return false;

			driveLetter = letter;
			return true;
		}
	}
}

