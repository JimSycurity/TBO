using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading;
using Titanis;
using Titanis.Smb2;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Get, "TBOSmbStreams")]
	[OutputType(typeof(FileStreamInfo))]
	public sealed class GetTBOSmbStreams : SmbCmdlet
	{
		private const string PathParameterSet = "Path";
		private const string LiteralPathParameterSet = "LiteralPath";

		[Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet)]
		public string[] Path { get; set; } = Array.Empty<string>();

		[Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet)]
		[Alias("PSPath")]
		public string[] LiteralPath { get; set; } = Array.Empty<string>();

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(SmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			foreach (var path in GetTargetPaths())
			{
				var uncPath = ResolveToUncPath(path, this.ParameterSetName);
				if (string.IsNullOrEmpty(uncPath.ShareName))
					throw new ArgumentException($"The UNC path must include a share name: {uncPath}", this.ParameterSetName);

				var snapshotPath = ResolveSnapshotPath(uncPath);
				if (string.IsNullOrEmpty(snapshotPath.ResolvedPath.ShareRelativePath))
					throw new ArgumentException("Path must include a file or directory name.", this.ParameterSetName);

				var streams = ReadStreams(smb, snapshotPath, cancellationToken);
				foreach (var stream in streams)
				{
					this.WriteObject(stream);
				}
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private IEnumerable<string> GetTargetPaths()
		{
			return this.ParameterSetName == LiteralPathParameterSet
				? this.LiteralPath
				: this.Path;
		}

		private static FileStreamInfo[] ReadStreams(
			SmbProviderInfo smb,
			SnapshotPath snapshotPath,
			CancellationToken cancellationToken)
		{
			Smb2OpenFileObjectBase? file = null;
			try
			{
				var createInfo = new Smb2CreateInfo
				{
					OplockLevel = Smb2OplockLevel.None,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					DesiredAccess = (uint)Smb2FileAccessRights.ReadAttributes,
					FileAttributes = Winterop.FileAttributes.ReparsePoint,
					ShareAccess = Smb2ShareAccess.ReadWriteDelete,
					CreateDisposition = Smb2CreateDisposition.Open,
					CreateOptions = Smb2FileCreateOptions.None,
					RequestMaximalAccess = true,
					QueryOnDiskId = true,
					TimeWarpToken = snapshotPath.TimeWarpToken
				};

				file = smb.SmbClient.CreateFileAsync(snapshotPath.ResolvedPath, createInfo, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();
				return file.GetStreamsInfoAsync(cancellationToken).GetAwaiter().GetResult();
			}
			finally
			{
				if (file != null)
					file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
			}
		}

		private static SnapshotPath ResolveSnapshotPath(UncPath uncPath)
		{
			if (TrySplitTimeWarpToken(uncPath, out var resolvedPath, out var timeWarpToken))
				return new SnapshotPath(resolvedPath, timeWarpToken);

			return new SnapshotPath(uncPath, null);
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

		private UncPath ResolveToUncPath(string path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", paramName);

			if (UncPath.TryParse(path, out var uncPath) && uncPath != null)
				return uncPath;

			ProviderInfo? providerInfo;
			PSDriveInfo? driveInfo;
			string providerPath;
			try
			{
				providerPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out providerInfo, out driveInfo);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"Path could not be resolved: {path}", paramName, ex);
			}

			if (providerInfo == null || !providerInfo.Name.Equals(SmbProvider.ProviderName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Path must be a UNC path or a {SmbProvider.ProviderName} PSDrive path: {path}", paramName);

			if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
				return resolvedUnc;

			throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
		}

		private readonly struct SnapshotPath
		{
			public SnapshotPath(UncPath resolvedPath, DateTime? timeWarpToken)
			{
				ResolvedPath = resolvedPath;
				TimeWarpToken = timeWarpToken;
			}

			public UncPath ResolvedPath { get; }
			public DateTime? TimeWarpToken { get; }
		}
	}
}
