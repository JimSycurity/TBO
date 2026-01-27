using System;
using System.Management.Automation;
using System.Threading;
using Titanis.Msrpc.Mswkst;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Get, "TBOSmbShares")]
	[OutputType(typeof(ShareInfo))]
	public sealed class GetTBOSmbShares : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public ShareInfoLevel Level { get; set; }

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

			var level = this.Level == 0 ? ShareInfoLevel.Level503 : this.Level;
			var bufferSize = this.BufferSize == 0 ? (int)ServerServiceClient.DefaultReturnBufferSize : this.BufferSize;

			using var session = smb.OpenServerServiceSessionAsync(serverName, cancellationToken).GetAwaiter().GetResult();
			try
			{
				var shares = session.Client.GetShares(
					@"\\" + serverName,
					level,
					bufferSize,
					cancellationToken).GetAwaiter().GetResult();

				foreach (var share in shares)
				{
					this.WriteObject(share);
				}
			}
			catch (Exception ex)
			{
				smb.LogException("Get-TBOSmbShares failed to enumerate shares", ex);
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
	}
}
