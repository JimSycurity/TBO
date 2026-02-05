using System;
using System.Management.Automation;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Set, "TBORegConnectOptions")]
	[Obsolete("Use Set-TBOConnectOptions.")]
	public sealed class SetTBORegConnectOptions : SetTBOConnectOptionsBase
	{
		protected override string DefaultScopeMessage
			=> "Setting default registry connection parameters (no server specified)";
	}
}
