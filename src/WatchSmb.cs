using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using Titanis;
using Titanis.Smb2;
using Titanis.Winterop;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet("Watch", "TBOSmb")]
	[OutputType(typeof(FileChangeNotification))]
	public sealed class WatchTBOSmb : SmbCmdlet
	{
		private const string PathParameterSet = "Path";
		private const string LiteralPathParameterSet = "LiteralPath";
		private const int DefaultBufferSize = 2048;

		[Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet)]
		public string[] Path { get; set; } = Array.Empty<string>();

		[Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet)]
		[Alias("PSPath")]
		public string[] LiteralPath { get; set; } = Array.Empty<string>();

		[Parameter]
		public SwitchParameter Recursive { get; set; }

		[Parameter]
		public int BufferSize { get; set; } = DefaultBufferSize;

		[Parameter]
		public SwitchParameter ContinueOnErrors { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(SmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			foreach (var path in GetTargetPaths())
			{
				var uncPath = ResolveToUncPath(path, this.ParameterSetName);
				ValidatePath(uncPath);
				Watch(smb, uncPath, this._cancelSource.Token);
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

		private void Watch(SmbProviderInfo smb, UncPath uncPath, CancellationToken cancellationToken)
		{
			if (this.BufferSize <= 0)
				this.BufferSize = DefaultBufferSize;

			var createInfo = new Smb2CreateInfo
			{
				CreateDisposition = Smb2CreateDisposition.Open,
				Priority = Smb2Priority.OpenDir,
				DesiredAccess = (uint)Smb2AccessRights.DefaultOpenDirAccess,
				ShareAccess = Smb2ShareAccess.DefaultDirShare,
				FileAttributes = Winterop.FileAttributes.None,
				CreateOptions = Smb2FileCreateOptions.Directory
					| Smb2FileCreateOptions.SynchronousIoNonalert
					| Smb2FileCreateOptions.OpenForBackupIntent,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				RequestMaximalAccess = true,
				QueryOnDiskId = true,
				OplockLevel = Smb2OplockLevel.Lease
			};

			Smb2Directory? dir = null;
			try
			{
				dir = (Smb2Directory)smb.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();

				WatchOptions options = WatchOptions.None;
				if (this.ContinueOnErrors.IsPresent)
					options |= WatchOptions.ContinueOnError;
				if (this.Recursive.IsPresent)
					options |= WatchOptions.WatchSubtree;

				this.WriteVerbose($"Watching for changes to {uncPath}{(this.Recursive.IsPresent ? " and subdirectories" : null)}. Press CTRL+C to stop.");
				var changeEnum = dir.ReadChangesAsync(Smb2ChangeFilter.All, options, this.BufferSize).GetAsyncEnumerator(cancellationToken);

				try
				{
					while (true)
					{
						var hasNext = changeEnum.MoveNextAsync().AsTask().GetAwaiter().GetResult();
						if (!hasNext)
							break;

						this.WriteObject(changeEnum.Current);
					}
				}
				finally
				{
					changeEnum.DisposeAsync().AsTask().GetAwaiter().GetResult();
				}
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
			}
			finally
			{
				if (dir != null)
					dir.CloseAsync(cancellationToken).GetAwaiter().GetResult();
			}
		}

		private static void ValidatePath(UncPath uncPath)
		{
			if (string.IsNullOrEmpty(uncPath.ShareName))
				throw new ArgumentException($"The UNC path must include a share name: {uncPath}");

			if (HasTimeWarpToken(uncPath))
				throw new NotSupportedException("Snapshot paths are read-only and cannot be watched.");
		}

		private static bool HasTimeWarpToken(UncPath uncPath)
		{
			var relativePath = uncPath.ShareRelativePath;
			if (string.IsNullOrEmpty(relativePath))
				return false;

			var separatorIndex = relativePath.IndexOf('\\');
			var firstSegment = separatorIndex >= 0 ? relativePath.Substring(0, separatorIndex) : relativePath;
			if (!firstSegment.StartsWith("@GMT-", StringComparison.OrdinalIgnoreCase))
				return false;

			try
			{
				_ = FileSnapshotInfo.Parse(firstSegment.ToUpperInvariant());
				return true;
			}
			catch
			{
				return false;
			}
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
	}
}
