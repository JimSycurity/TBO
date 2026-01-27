using System.Management.Automation;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommunications.Disconnect, "TBOSmbServer", DefaultParameterSetName = ParameterSetNames.Server)]
	public sealed class DisconnectTBOSmbServer : SmbCmdlet
	{
		private static class ParameterSetNames
		{
			public const string Server = "Server";
			public const string All = "All";
		}

		[Parameter(Mandatory = true, Position = 0, ParameterSetName = ParameterSetNames.Server, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[ValidateNotNullOrEmpty]
		public string ServerName { get; set; } = string.Empty;

		[Parameter(ParameterSetName = ParameterSetNames.Server)]
		[ValidateRange(1, 65535)]
		public int? RemotePort { get; set; }

		[Parameter(Mandatory = true, ParameterSetName = ParameterSetNames.All)]
		public SwitchParameter All { get; set; }

		protected override void ProcessRecord(SmbProviderInfo smb)
		{
			if (this.ParameterSetName == ParameterSetNames.All)
			{
				smb.DisconnectAllAsync().GetAwaiter().GetResult();
				return;
			}

			smb.DisconnectServerAsync(this.ServerName, this.RemotePort).GetAwaiter().GetResult();
		}
	}
}
