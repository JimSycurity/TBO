using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading;
using Titanis;
using Titanis.Smb2;
using Titanis.Winterop;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Get, "TBOSmbSnapshots")]
	[OutputType(typeof(FileSnapshotInfo))]
	public sealed class GetTBOSmbSnapshots : SmbCmdlet
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

			foreach (var path in GetTargetPaths())
			{
				var uncPath = ResolveToUncPath(path, this.ParameterSetName);
				var snapshotInfo = ReadSnapshots(smb, uncPath, this._cancelSource.Token);

				foreach (var snapshot in snapshotInfo.Snapshots)
				{
					this.WriteObject(snapshot);
				}

				this.WriteVerbose($"Total snapshots: {snapshotInfo.TotalSnapshots}");
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

		private static FileSnapshotsInfo ReadSnapshots(
			SmbProviderInfo smb,
			UncPath uncPath,
			CancellationToken cancellationToken)
		{
			Smb2OpenFileObjectBase? file = null;
			try
			{
				var createInfo = new Smb2CreateInfo
				{
					OplockLevel = Smb2OplockLevel.None,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					DesiredAccess = (uint)(Smb2AccessRights.ReadAttributes | Smb2AccessRights.ReadData | Smb2AccessRights.Synchronize),
					FileAttributes = Winterop.FileAttributes.ReparsePoint,
					ShareAccess = Smb2ShareAccess.ReadWrite,
					CreateDisposition = Smb2CreateDisposition.Open,
					CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert,
					RequestMaximalAccess = true,
					QueryOnDiskId = false
				};

				file = smb.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();
				return file.GetSnapshotInfoAsync(cancellationToken).GetAwaiter().GetResult();
			}
			finally
			{
				if (file != null)
					file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
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
