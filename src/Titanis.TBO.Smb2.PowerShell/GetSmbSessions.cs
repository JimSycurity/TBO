using System;
using System.Management.Automation;
using System.Threading;
using Titanis.Msrpc.Mswkst;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Get, "TBOSmbSessions")]
	[OutputType(typeof(SessionInfo))]
	public sealed class GetTBOSmbSessions : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public SessionInfoLevel Level { get; set; }

		[Parameter]
		public string? ClientComputer { get; set; }

		[Parameter]
		public string? ClientUserName { get; set; }

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

			var level = this.Level == 0 ? SessionInfoLevel.Level502 : this.Level;
			var bufferSize = this.BufferSize == 0 ? (int)ServerServiceClient.DefaultReturnBufferSize : this.BufferSize;
			var clientComputer = NormalizeClientComputer(this.ClientComputer);

			ValidateFilters();

			using var session = smb.OpenServerServiceSessionAsync(serverName, cancellationToken).GetAwaiter().GetResult();
			try
			{
				var sessions = session.Client.GetSessions(
					@"\\" + serverName,
					clientComputer,
					this.ClientUserName,
					level,
					bufferSize,
					cancellationToken).GetAwaiter().GetResult();

				foreach (var entry in sessions)
				{
					this.WriteObject(entry);
				}
			}
			catch (Exception ex)
			{
				smb.LogException("Get-TBOSmbSessions failed to enumerate sessions", ex);
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

		private static string? NormalizeClientComputer(string? clientComputer)
		{
			if (string.IsNullOrWhiteSpace(clientComputer))
				return null;

			return clientComputer.StartsWith(@"\\", StringComparison.Ordinal)
				? clientComputer
				: @"\\" + clientComputer;
		}

		private void ValidateFilters()
		{
			if (this.ClientUserName != null && this.ClientUserName.IndexOfAny(new char[] { '\\', '@' }) >= 0)
				this.WriteWarning("The -ClientUserName user should not specify a domain name. This will likely return no results.");
		}
	}
}
