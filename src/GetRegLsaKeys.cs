using System;
using System.Management.Automation;
using System.Threading;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegLsaKeyInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string? BootKey { get; init; }
		public byte[]? BootKeyBytes { get; init; }
		public string? LsaKey { get; init; }
		public byte[]? LsaKeyBytes { get; init; }
		public string? LsaKeySource { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegLsaKeys")]
	[OutputType(typeof(TboRegLsaKeyInfo))]
	public sealed class GetTBORegLsaKeys : TboRegLsaSecretCmdlet
	{
		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				byte[]? bootKey = null;
				byte[]? lsaKey = null;
				string? lsaKeySource = null;

				try
				{
					bootKey = ResolveBootKey(smb, session, cancellationToken);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBORegLsaKeys failed to derive the boot key from {this.ServerName}", ex);
					this.LogWarning(smb, $"Get-TBORegLsaKeys failed to derive the boot key: {ex.Message}");
				}

				if (bootKey != null)
				{
					try
					{
						lsaKey = ResolveLsaKey(smb, session, cancellationToken, null, null, "LsaKey", out lsaKeySource);
					}
					catch (Exception ex)
					{
						this.LogException(smb, $"Get-TBORegLsaKeys failed to derive the LSA key from {this.ServerName}", ex);
						this.LogWarning(smb, $"Get-TBORegLsaKeys failed to derive the LSA key: {ex.Message}");
					}
				}

				this.WriteObject(new TboRegLsaKeyInfo
				{
					ServerName = this.ServerName,
					BootKeyBytes = bootKey,
					BootKey = bootKey != null ? bootKey.ToHexString() : null,
					LsaKeyBytes = lsaKey,
					LsaKey = lsaKey != null ? lsaKey.ToHexString() : null,
					LsaKeySource = lsaKeySource
				});
			});
		}
	}
}
