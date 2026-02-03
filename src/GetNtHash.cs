using System;
using System.Management.Automation;
using System.Text;
using Titanis.Crypto;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboNtHashInfo
	{
		public byte[]? NtlmHash { get; init; }
		public string? NtlmHashText { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBONtHash")]
	[OutputType(typeof(TboNtHashInfo))]
	public sealed class GetTBONtHash : PSCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		public string Password { get; set; } = string.Empty;

		protected override void ProcessRecord()
		{
			var input = this.Password ?? string.Empty;
			var bytes = Encoding.Unicode.GetBytes(input);
			var hash = SlimHashAlgorithm.ComputeHash<Md4Context>(bytes);

			this.WriteObject(new TboNtHashInfo
			{
				NtlmHash = hash,
				NtlmHashText = hash?.ToHexString()
			});
		}
	}
}
