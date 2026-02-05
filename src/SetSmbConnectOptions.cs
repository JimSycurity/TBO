using System;
using System.Management.Automation;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public abstract class SmbCmdlet : PSCmdlet
	{
		internal static ISmbProviderInfo? ProviderInfoOverride { get; set; }

		protected override void ProcessRecord()
		{
			var smb = ProviderInfoOverride ?? (ISmbProviderInfo)this.SessionState.Provider.GetOne(SmbProvider.ProviderName);
			this.ProcessRecord(smb);
		}

		protected abstract void ProcessRecord(ISmbProviderInfo smb);
	}

	public abstract class SetTBOConnectOptionsBase : SmbCmdlet, IDynamicParameters
	{
		[Parameter(Position = 0)]
		public string? ServerName { get; set; }

		private readonly SmbConnectionParameters _parms = new SmbConnectionParameters();
		public object GetDynamicParameters()
			=> this._parms;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			if (string.IsNullOrEmpty(this.ServerName))
			{
				this.WriteVerbose(this.DefaultScopeMessage);
				var baseParams = GetDefaultConnectParameters(smb);
				smb.DefaultConnectParameters = this._parms.MergeOnto(baseParams);
				return;
			}

			var baseServerParams = GetServerConnectParameters(smb, this.ServerName);
			var parms = this._parms.MergeOnto(baseServerParams);
			smb.SetConnectParameters(this.ServerName, parms);
		}

		protected virtual string DefaultScopeMessage
			=> "Setting default connection parameters (no server specified)";

		private static SmbConnectionParameters GetDefaultConnectParameters(ISmbProviderInfo smb)
			=> smb.DefaultConnectParameters as SmbConnectionParameters ?? SmbConnectionParameters.GetDefault();

		private static SmbConnectionParameters GetServerConnectParameters(ISmbProviderInfo smb, string serverName)
		{
			var existing = smb.GetConnectParametersFor(serverName, false) as SmbConnectionParameters;
			return existing ?? GetDefaultConnectParameters(smb);
		}
	}

	[Cmdlet(VerbsCommon.Set, "TBOConnectOptions")]
	public sealed class SetTBOConnectOptions : SetTBOConnectOptionsBase
	{
	}

	[Cmdlet(VerbsCommon.Set, "TBOSmbConnectOptions")]
	[Obsolete("Use Set-TBOConnectOptions.")]
	public sealed class SetTBOSmbConnectOptions : SetTBOConnectOptionsBase
	{
		protected override string DefaultScopeMessage
			=> "Setting default SMB connection parameters (no server specified)";
	}
}
