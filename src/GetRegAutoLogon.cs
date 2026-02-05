using System;
using System.Management.Automation;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegAutoLogonInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string KeyPath { get; init; } = string.Empty;
		public string? DefaultUserName { get; init; }
		public string? DefaultDomainName { get; init; }
		public string? DefaultPassword { get; init; }
		public string? AltDefaultUserName { get; init; }
		public string? AltDefaultDomainName { get; init; }
		public string? AltDefaultPassword { get; init; }
		public string? DefaultLogonDomain { get; init; }
		public string? AutoAdminLogon { get; init; }
		public string? ForceAutoLogon { get; init; }
		public string? AutoLogonCount { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegAutoLogon")]
	[OutputType(typeof(TboRegAutoLogonInfo))]
	public sealed class GetTBORegAutoLogon : TboRegCmdlet
	{
		private const string WinlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var winlogonSpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				WinlogonPath);

			try
			{
				ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					var winlogonKey = RegistryHelpers.TryOpenKey(
						session.Client,
						winlogonSpec,
						RegistryAccessRights.QueryValue,
						cancellationToken);
					if (winlogonKey == null)
					{
						this.LogWarning(smb, $"Get-TBORegAutoLogon could not open {winlogonSpec.KeyPath} on {this.ServerName}.");
						return;
					}

					using (winlogonKey)
					{
						this.WriteObject(new TboRegAutoLogonInfo
						{
							ServerName = this.ServerName,
							KeyPath = winlogonSpec.KeyPath,
							DefaultUserName = RegistryHelpers.TryReadValueString(winlogonKey, "DefaultUserName", cancellationToken),
							DefaultDomainName = RegistryHelpers.TryReadValueString(winlogonKey, "DefaultDomainName", cancellationToken),
							DefaultPassword = RegistryHelpers.TryReadValueString(winlogonKey, "DefaultPassword", cancellationToken),
							AltDefaultUserName = RegistryHelpers.TryReadValueString(winlogonKey, "AltDefaultUserName", cancellationToken),
							AltDefaultDomainName = RegistryHelpers.TryReadValueString(winlogonKey, "AltDefaultDomainName", cancellationToken),
							AltDefaultPassword = RegistryHelpers.TryReadValueString(winlogonKey, "AltDefaultPassword", cancellationToken),
							DefaultLogonDomain = RegistryHelpers.TryReadValueString(winlogonKey, "DefaultLogonDomain", cancellationToken),
							AutoAdminLogon = RegistryHelpers.TryReadValueString(winlogonKey, "AutoAdminLogon", cancellationToken),
							ForceAutoLogon = RegistryHelpers.TryReadValueString(winlogonKey, "ForceAutoLogon", cancellationToken),
							AutoLogonCount = RegistryHelpers.TryReadValueString(winlogonKey, "AutoLogonCount", cancellationToken)
						});
					}
				});
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				this.LogException(smb, $"Get-TBORegAutoLogon failed to read {winlogonSpec.KeyPath}", ex);
				this.LogWarning(smb, $"Get-TBORegAutoLogon could not read autologon registry values: {ex.Message}");
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBORegAutoLogon failed to read {winlogonSpec.KeyPath}", ex);
				this.LogWarning(smb, $"Get-TBORegAutoLogon could not read autologon registry values: {ex.Message}");
			}
		}
	}
}
