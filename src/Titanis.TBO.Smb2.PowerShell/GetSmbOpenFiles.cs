using System;
using System.Management.Automation;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Mswkst;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Get, "TBOSmbOpenFiles")]
	[OutputType(typeof(OpenFileInfo))]
	public sealed class GetTBOSmbOpenFiles : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public OpenFileInfoLevel Level { get; set; }

		[Parameter]
		public string? OpenBy { get; set; }

		[Parameter]
		public string? BasePath { get; set; }

		[Parameter]
		public int BufferSize { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(SmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var basePath = ResolveBasePath(this.BasePath, nameof(this.BasePath));
			var level = this.Level == 0 ? OpenFileInfoLevel.Level3 : this.Level;
			var bufferSize = this.BufferSize == 0 ? (int)ServerServiceClient.DefaultReturnBufferSize : this.BufferSize;

			ValidateFilters(basePath);

			using var session = smb.OpenServerServiceSessionAsync(serverName, cancellationToken).GetAwaiter().GetResult();
			try
			{
				var files = session.Client.GetOpenFiles(
					@"\\" + serverName,
					basePath,
					this.OpenBy,
					level,
					bufferSize,
					cancellationToken).GetAwaiter().GetResult();

				foreach (var file in files)
				{
					this.WriteObject(file);
				}
			}
			catch (Exception ex)
			{
				smb.LogException("Get-TBOSmbOpenFiles failed to enumerate open files", ex);
				throw;
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private static string NormalizeServerName(string? serverName)
		{
			return string.IsNullOrWhiteSpace(serverName)
				? string.Empty
				: serverName.TrimStart('\\');
		}

		private string? ResolveBasePath(string? path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				return null;

			if (UncPath.TryParse(path, out var uncPath) && uncPath != null)
				return uncPath.ToString();

			ProviderInfo? providerInfo;
			PSDriveInfo? driveInfo;
			string providerPath;
			try
			{
				providerPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out providerInfo, out driveInfo);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"BasePath could not be resolved: {path}", paramName, ex);
			}

			if (providerInfo != null && providerInfo.Name.Equals(SmbProvider.ProviderName, StringComparison.OrdinalIgnoreCase))
			{
				if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
					return resolvedUnc.ToString();

				throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
			}

			return path;
		}

		private void ValidateFilters(string? basePath)
		{
			if (this.OpenBy != null && this.OpenBy.IndexOfAny(new char[] { '\\', '@' }) >= 0)
				this.WriteWarning("The -OpenBy user should not specify a domain name. This will likely return no results.");

			if (string.IsNullOrWhiteSpace(basePath))
				return;

			if (!(basePath.StartsWith(@"\\", StringComparison.Ordinal) || (basePath.Length >= 2 && basePath[1] == ':')))
				this.WriteWarning("The -BasePath should begin with \\\\ to filter results to open pipes, or with X: (where X is a drive letter) to filter the results to open files on a drive.");
			if (WildcardPattern.ContainsWildcardCharacters(basePath))
				this.WriteWarning("-BasePath does not support wildcards.");
		}
	}
}
