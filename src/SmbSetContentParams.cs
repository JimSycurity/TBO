using System.Text;
using System.Management.Automation;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class SmbSetContentParams
	{
		[Parameter]
		public SwitchParameter NoNewline { get; set; }

		[Parameter]
		public Encoding? Encoding { get; set; }
	}
}
