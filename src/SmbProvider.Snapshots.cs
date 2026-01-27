using System;
using Titanis;
using Titanis.Smb2;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProvider
	{
		private readonly struct SnapshotPath
		{
			public SnapshotPath(UncPath originalPath, UncPath resolvedPath, DateTime? timeWarpToken)
			{
				OriginalPath = originalPath;
				ResolvedPath = resolvedPath;
				TimeWarpToken = timeWarpToken;
			}

			public UncPath OriginalPath { get; }
			public UncPath ResolvedPath { get; }
			public DateTime? TimeWarpToken { get; }
			public bool HasTimeWarpToken => TimeWarpToken.HasValue;
		}

		private static SnapshotPath ResolveSnapshotPath(string path)
		{
			var uncPath = UncPath.Parse(path);
			return ResolveSnapshotPath(uncPath);
		}

		private static SnapshotPath ResolveSnapshotPath(UncPath uncPath)
		{
			if (TrySplitTimeWarpToken(uncPath, out var resolvedPath, out var timeWarpToken))
				return new SnapshotPath(uncPath, resolvedPath, timeWarpToken);

			return new SnapshotPath(uncPath, uncPath, null);
		}

		private static bool TrySplitTimeWarpToken(UncPath uncPath, out UncPath resolvedPath, out DateTime? timeWarpToken)
		{
			resolvedPath = uncPath;
			timeWarpToken = null;

			var relativePath = uncPath.ShareRelativePath;
			if (string.IsNullOrEmpty(relativePath))
				return false;

			var separatorIndex = relativePath.IndexOf('\\');
			var firstSegment = separatorIndex >= 0 ? relativePath.Substring(0, separatorIndex) : relativePath;
			if (!firstSegment.StartsWith("@GMT-", StringComparison.OrdinalIgnoreCase))
				return false;

			try
			{
				var snapshot = FileSnapshotInfo.Parse(firstSegment.ToUpperInvariant());
				timeWarpToken = snapshot.Timestamp;
			}
			catch
			{
				return false;
			}

			var remainder = separatorIndex >= 0 ? relativePath.Substring(separatorIndex + 1) : null;
			resolvedPath = string.IsNullOrEmpty(remainder)
				? new UncPath(uncPath.ServerName, uncPath.Port, uncPath.ShareName, string.Empty)
				: new UncPath(uncPath.ServerName, uncPath.Port, uncPath.ShareName, remainder);
			return true;
		}
	}
}
