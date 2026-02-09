using System;
using System.Collections.Generic;
using System.Globalization;
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

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();

			Action<string>? logDiagnostic = null;
			Action<string>? logWarning = null;
			if (smb is SmbProviderInfo provider)
			{
				logDiagnostic = provider.LogDiagnostic;
				logWarning = provider.LogWarning;
			}

			foreach (var path in GetTargetPaths())
			{
				var uncPath = ResolveToUncPath(path, this.ParameterSetName);

				// Local-mode uses \\localhost\<Drive>$ admin-share UNC paths but must not attempt SMB authentication.
				if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
				{
					var shareName = uncPath.ShareName;
					if (string.IsNullOrEmpty(shareName))
						throw new InvalidOperationException($"UNC path '{uncPath}' did not include a share name.");

					var driveRoot = GetDriveRoot(shareName);
					if (!LocalVssShadowCopyResolver.TryListShadowCopies(driveRoot, logDiagnostic, logWarning, out var shadowCopies, out var listFailure))
						throw new InvalidOperationException(listFailure ?? $"Failed to enumerate VSS shadow copies for '{driveRoot}'.");

					foreach (var shadowCopy in shadowCopies)
					{
						var token = "@GMT-" + shadowCopy.InstallDateUtc.ToString("yyyy.MM.dd-HH.mm.ss", CultureInfo.InvariantCulture);
						this.WriteObject(FileSnapshotInfo.Parse(token));
					}

					this.WriteVerbose($"Total snapshots: {shadowCopies.Count}");
					continue;
				}

				var snapshotInfo = ReadSnapshots(smb, uncPath, this._cancelSource.Token);

				foreach (var snapshot in snapshotInfo.Snapshots)
					this.WriteObject(snapshot);

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
			ISmbProviderInfo smb,
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

		private static string GetDriveRoot(string shareName)
		{
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("UNC share name must be provided.", nameof(shareName));

			var trimmed = shareName.Trim().Trim('\\');
			if (trimmed.Length == 2 && char.IsLetter(trimmed[0]) && trimmed[1] == '$')
				return $"{char.ToUpperInvariant(trimmed[0])}:\\";

			throw new ArgumentException($"UNC share '{shareName}' is not a supported local admin share. Expected '<DriveLetter>$' (ex: 'C$').", nameof(shareName));
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
