using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Security.AccessControl;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using Titanis;
using Titanis.Smb2;
using Titanis.Winterop.Security;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Get, "TBOSmbSecurityDescriptor")]
	public sealed class GetTBOSmbSecurityDescriptor : SmbCmdlet
	{
		private const string PathParameterSet = "Path";
		private const string LiteralPathParameterSet = "LiteralPath";
		private const int DefaultSecurityDescriptorBufferSize = 8192;

		[Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet)]
		public string[] Path { get; set; } = Array.Empty<string>();

		[Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet)]
		[Alias("PSPath")]
		public string[] LiteralPath { get; set; } = Array.Empty<string>();

		[Parameter]
		public SwitchParameter AsSddl { get; set; }

		[Parameter]
		public SwitchParameter AsBytes { get; set; }

		[Parameter]
		public SwitchParameter AsWindows { get; set; }

		[Parameter]
		public SecurityInfo Sections { get; set; } = SecurityInfo.Owner | SecurityInfo.Group | SecurityInfo.Dacl;

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			if (this.AsWindows.IsPresent && !RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				throw new NotSupportedException("AsWindows is only supported on Windows.");
			if (this.Sections == SecurityInfo.None)
				throw new ArgumentException("Sections must include at least one SecurityInfo flag.", nameof(Sections));
			var format = SecurityDescriptorHelpers.ResolveFormat(this.AsSddl, this.AsBytes, this.AsWindows);

			foreach (var path in GetTargetPaths())
			{
				var uncPath = ResolveToUncPath(path, this.ParameterSetName);
				var securityDescriptor = ReadSecurityDescriptor(smb, uncPath, this.Sections, this._cancelSource.Token);
				if (securityDescriptor == null)
				{
					this.WriteWarning($"No security descriptor was returned for '{uncPath}'.");
					continue;
				}

				this.WriteObject(SecurityDescriptorHelpers.Format(securityDescriptor, format));
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

		private SecurityDescriptor? ReadSecurityDescriptor(
			ISmbProviderInfo smb,
			UncPath uncPath,
			SecurityInfo sections,
			CancellationToken cancellationToken)
		{
			if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
			{
				var provider = smb as SmbProviderInfo;
				Action<string>? logDiagnostic = provider != null ? provider.LogDiagnostic : null;
				Action<string>? logWarning = provider != null ? provider.LogWarning : null;
					return LocalNtfsSecurityDescriptor.Read(
						uncPath,
						timeWarpToken: null,
						sections,
						logDiagnostic: logDiagnostic,
						logWarning: logWarning,
						cancellationToken: cancellationToken);
			}

			Smb2OpenFileObjectBase? file = null;
			try
			{
				var desiredAccess = Smb2AccessRights.ReadControl;
				if (sections.HasFlag(SecurityInfo.Sacl))
					desiredAccess |= Smb2AccessRights.AccessSystemSecurity;

				var createInfo = new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)desiredAccess,
					ShareAccess = Smb2ShareAccess.ReadWriteDelete,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert,
					FileAttributes = Winterop.FileAttributes.Normal
				};

				file = smb.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();
				return file.GetSecurityAsync(
					sections,
					DefaultSecurityDescriptorBufferSize,
					cancellationToken).GetAwaiter().GetResult();
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

	[Cmdlet(VerbsCommon.Set, "TBOSmbSecurityDescriptor", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class SetTBOSmbSecurityDescriptor : SmbCmdlet
	{
		private const string PathParameterSet = "Path";
		private const string LiteralPathParameterSet = "LiteralPath";

		[Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet)]
		public string[] Path { get; set; } = Array.Empty<string>();

		[Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet)]
		[Alias("PSPath")]
		public string[] LiteralPath { get; set; } = Array.Empty<string>();

		[Parameter(Mandatory = true, Position = 1)]
		public object SecurityDescriptor { get; set; } = null!;

		[Parameter]
		public SecurityInfo Sections { get; set; } = SecurityInfo.Owner | SecurityInfo.Group | SecurityInfo.Dacl;

		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();

			var recordActivity = this.ResolveCacheIngestionEnabled(this.Cache);

			var resolvedDescriptor = SecurityDescriptorInputHelpers.ResolveSecurityDescriptor(this.SecurityDescriptor, allowRegistryBinaryBytes: false);
			var securityInfo = SecurityDescriptorInputHelpers.ResolveSecurityInfo(resolvedDescriptor, this.Sections);

			foreach (var path in GetTargetPaths())
			{
				var uncPath = ResolveToUncPath(path, this.ParameterSetName);
				if (!this.ShouldProcess(uncPath.ToString(), "Set security descriptor"))
					continue;
				WriteSecurityDescriptor(smb, uncPath, resolvedDescriptor, securityInfo, recordActivity, this.CachePath, this._cancelSource.Token);
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

		private void WriteSecurityDescriptor(
			ISmbProviderInfo smb,
			UncPath uncPath,
			SecurityDescriptor securityDescriptor,
			SecurityInfo securityInfo,
			bool recordActivity,
			string? cachePath,
			CancellationToken cancellationToken)
		{
			var target = uncPath.ToString();
			var afterBytes = securityDescriptor.ToByteArray();
			byte[]? beforeBytes = null;
			string? beforeReadFailure = null;
			Exception? operationFailure = null;
			Smb2OpenFileObjectBase? file = null;

			try
			{
				if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
				{
					var provider = smb as SmbProviderInfo;
					Action<string>? logDiagnostic = provider != null ? provider.LogDiagnostic : null;
					Action<string>? logWarning = provider != null ? provider.LogWarning : null;

					if (recordActivity)
					{
						try
						{
							var existing = LocalNtfsSecurityDescriptor.Read(
								uncPath,
								timeWarpToken: null,
								securityInfo,
								logDiagnostic: logDiagnostic,
								logWarning: logWarning,
								cancellationToken: cancellationToken);
							beforeBytes = existing.ToByteArray();
						}
						catch (Exception ex)
						{
							beforeReadFailure = ex.Message;
							beforeBytes = null;
						}
					}

					LocalNtfsSecurityDescriptor.Write(
						uncPath,
						timeWarpToken: null,
						securityDescriptor,
						securityInfo,
						logDiagnostic: logDiagnostic,
						logWarning: logWarning,
						cancellationToken: cancellationToken);
					return;
				}

				var desiredAccess = Smb2AccessRights.WriteDac | Smb2AccessRights.WriteOwner | Smb2AccessRights.ReadControl;
				if (securityInfo.HasFlag(SecurityInfo.Sacl))
					desiredAccess |= Smb2AccessRights.AccessSystemSecurity;

				var createInfo = new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)desiredAccess,
					ShareAccess = Smb2ShareAccess.ReadWriteDelete,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert,
					FileAttributes = Winterop.FileAttributes.Normal
				};

				file = smb.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.ReadWrite, cancellationToken).GetAwaiter().GetResult();
				if (file == null)
					throw new InvalidOperationException($"SMB CreateFile returned null for '{uncPath}'.");

				if (recordActivity)
				{
					try
					{
						var existing = file.GetSecurityAsync(securityInfo, 8192, cancellationToken).GetAwaiter().GetResult();
						beforeBytes = existing.ToByteArray();
					}
					catch (Exception ex)
					{
						beforeReadFailure = ex.Message;
						beforeBytes = null;
					}
				}

				file.SetSecurityAsync(securityDescriptor, securityInfo, cancellationToken).GetAwaiter().GetResult();
			}
			catch (Exception ex)
			{
				operationFailure = ex;
				throw;
			}
			finally
			{
				if (file != null)
					file.CloseAsync(cancellationToken).GetAwaiter().GetResult();

				string? contextJson = null;
				if (recordActivity)
				{
					contextJson = JsonSerializer.Serialize(new
					{
						sections = securityInfo.ToString(),
						beforeReadFailure
					});
				}

				TboCacheWriteActivities.TryRecord(
					cmdlet: this,
					smb: smb,
					enabled: recordActivity,
					cachePath: cachePath,
					serverName: uncPath.ServerName,
					kind: TboCacheWriteActivities.KindFileSystem,
					action: TboCacheWriteActivities.ActionSetSecurityDescriptor,
					target: target,
					path: target,
					valueName: null,
					valueType: null,
					beforeBlobKind: beforeBytes != null ? TboCacheWriteActivities.BlobKindSecurityDescriptor : null,
					beforeBlob: beforeBytes,
					afterBlobKind: TboCacheWriteActivities.BlobKindSecurityDescriptor,
					afterBlob: afterBytes,
					contextJson: contextJson,
					success: operationFailure == null,
					failureReason: operationFailure?.Message);
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
