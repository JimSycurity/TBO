using System.Management.Automation;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Set, "TBORegConnectOptions")]
	public sealed class SetTBORegConnectOptions : SmbCmdlet, IDynamicParameters
	{
		[Parameter(Position = 0)]
		public string? ServerName { get; set; }

		private readonly SmbConnectionParameters _parms = new SmbConnectionParameters();
		public object GetDynamicParameters()
			=> this._parms;

		protected override void ProcessRecord(SmbProviderInfo smb)
		{
			if (string.IsNullOrEmpty(this.ServerName))
			{
				this.WriteVerbose("Setting default registry connection parameters (no server specified)");
				smb.DefaultConnectParameters = this._parms.MergeOnto(SmbConnectionParameters.GetDefault());
			}
			else
			{
				var parms = this._parms;
				parms = parms.MergeOnto(SmbConnectionParameters.GetDefault());
				smb.SetConnectParameters(this.ServerName, parms);
			}
		}
	}
}
