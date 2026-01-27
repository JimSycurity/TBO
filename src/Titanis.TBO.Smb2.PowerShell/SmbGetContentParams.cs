using System.Text;
using System.Management.Automation;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal class SmbGetContentParams
	{
		[Parameter]
		public SwitchParameter Raw { get; set; }

		[Parameter]
		public Encoding? Encoding { get; set; }
	}
}
