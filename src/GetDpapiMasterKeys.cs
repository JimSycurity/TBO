using System;
using System.Management.Automation;
using System.Threading;
using Titanis;
using Titanis.Net;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboDpapiMasterKeyInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Scope { get; init; } = string.Empty;
		public string? UserSid { get; init; }
		public string KeyPath { get; init; } = string.Empty;
		public string? MasterKeyGuid { get; init; }
		public bool IsPreferred { get; init; }
		public string? MasterKey { get; init; }
		public string? MasterKeyHash { get; init; }
		public string? FailureReason { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBODpapiMasterKeys")]
	[OutputType(typeof(TboDpapiMasterKeyInfo))]
	public sealed class GetTBODpapiMasterKeys : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public DpapiMasterKeyScope Scope { get; set; } = DpapiMasterKeyScope.All;

		[Parameter]
		public string ShareName { get; set; } = DpapiMasterKeyLocator.DefaultShareName;

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public string? DpapiMachineKey { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public string? DpapiUserKey { get; set; }

		[Parameter]
		public byte[]? DpapiMachineKeyBytes { get; set; }

		[Parameter]
		public byte[]? DpapiUserKeyBytes { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = DpapiHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var shareName = DpapiHelpers.NormalizeShareName(this.ShareName);
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("ShareName must be provided.", nameof(this.ShareName));

			var keys = ResolveDpapiKeys();
			if (keys.MachineKey == null && keys.UserKey == null)
			{
				this.WriteWarning("Get-TBODpapiMasterKeys did not receive DPAPI_SYSTEM key material. Supply DpapiMachineKey/DpapiUserKey or pipe Get-TBORegLsaSecrets.");
				return;
			}

			var locations = DpapiMasterKeyLocator.Enumerate(
				smb,
				serverName,
				shareName,
				this.Scope,
				message => this.WriteWarning(message),
				null,
				message => this.WriteVerbose(message),
				cancellationToken);

			foreach (var location in locations)
			{
				var keyMaterial = location.Scope.Equals("Machine", StringComparison.OrdinalIgnoreCase)
					? keys.MachineKey
					: keys.UserKey;
				if (keyMaterial == null)
				{
					this.WriteObject(new TboDpapiMasterKeyInfo
					{
						ServerName = this.ServerName,
						Scope = location.Scope,
						UserSid = location.UserSid,
						KeyPath = location.KeyPath,
						MasterKeyGuid = location.MasterKeyGuid,
						IsPreferred = location.IsPreferred,
						FailureReason = "No DPAPI_SYSTEM key material available for this scope."
					});
					continue;
				}

				byte[]? rawFile = null;
				try
				{
					rawFile = DpapiHelpers.ReadFileBytes(smb, UncPath.Parse(location.KeyPath), cancellationToken);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBODpapiMasterKeys failed to read {location.KeyPath}", ex, emitWarning: false);
					this.WriteObject(new TboDpapiMasterKeyInfo
					{
						ServerName = this.ServerName,
						Scope = location.Scope,
						UserSid = location.UserSid,
						KeyPath = location.KeyPath,
						MasterKeyGuid = location.MasterKeyGuid,
						IsPreferred = location.IsPreferred,
						FailureReason = $"Failed to read master key file: {ex.Message}"
					});
					continue;
				}

				DpapiMasterKeyFile? masterKeyFile = null;
				try
				{
					masterKeyFile = DpapiMasterKeyCrypto.ParseMasterKeyFile(rawFile);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBODpapiMasterKeys failed to parse {location.KeyPath}", ex, emitWarning: false);
					this.WriteObject(new TboDpapiMasterKeyInfo
					{
						ServerName = this.ServerName,
						Scope = location.Scope,
						UserSid = location.UserSid,
						KeyPath = location.KeyPath,
						MasterKeyGuid = location.MasterKeyGuid,
						IsPreferred = location.IsPreferred,
						FailureReason = $"Failed to parse master key file: {ex.Message}"
					});
					continue;
				}

				var parsedGuid = masterKeyFile.Guid?.ToString();
				var parsedGuidText = parsedGuid ?? masterKeyFile.GuidText?.Trim().Trim('{', '}');
				var masterKeyGuid = string.IsNullOrWhiteSpace(parsedGuidText)
					? location.MasterKeyGuid
					: parsedGuidText;

				if (!string.IsNullOrWhiteSpace(masterKeyGuid)
					&& !string.IsNullOrWhiteSpace(location.MasterKeyGuid)
					&& !string.Equals(masterKeyGuid, location.MasterKeyGuid, StringComparison.OrdinalIgnoreCase))
				{
					this.WriteVerbose($"Get-TBODpapiMasterKeys detected header GUID {masterKeyGuid} for {location.KeyPath} (path GUID {location.MasterKeyGuid}).");
				}

				var decryptResult = masterKeyFile.DecryptWithKey(keyMaterial);
				var bestResult = decryptResult.MasterKeyResult?.Success == true
					? decryptResult.MasterKeyResult
					: decryptResult.BackupKeyResult;
				var usedAlternateKey = false;

				if (bestResult?.Success != true)
				{
					var alternateKey = location.Scope.Equals("Machine", StringComparison.OrdinalIgnoreCase)
						? keys.UserKey
						: keys.MachineKey;
					if (alternateKey != null && alternateKey.Length > 0)
					{
						var alternateResult = masterKeyFile.DecryptWithKey(alternateKey);
						var alternateBest = alternateResult.MasterKeyResult?.Success == true
							? alternateResult.MasterKeyResult
							: alternateResult.BackupKeyResult;

						if (alternateBest?.Success == true)
						{
							decryptResult = alternateResult;
							bestResult = alternateBest;
							usedAlternateKey = true;
							this.WriteVerbose($"Get-TBODpapiMasterKeys decrypted {location.KeyPath} using the alternate DPAPI_SYSTEM key.");
						}
					}
				}

				if (bestResult != null && bestResult.Success && bestResult.MasterKey != null)
				{
					this.WriteObject(new TboDpapiMasterKeyInfo
					{
						ServerName = this.ServerName,
						Scope = location.Scope,
						UserSid = location.UserSid,
						KeyPath = location.KeyPath,
						MasterKeyGuid = masterKeyGuid,
						IsPreferred = location.IsPreferred,
						MasterKey = bestResult.MasterKey.ToHexString(),
						MasterKeyHash = bestResult.MasterKeyHash?.ToHexString()
					});
				}
				else
				{
					var masterReason = decryptResult.MasterKeyResult?.FailureReason;
					var backupReason = decryptResult.BackupKeyResult?.FailureReason;
					var reason = bestResult?.FailureReason ?? decryptResult.FailureReason ?? "Failed to decrypt master key.";
					if (!string.IsNullOrWhiteSpace(masterReason) || !string.IsNullOrWhiteSpace(backupReason))
					{
						reason = $"MasterKey: {masterReason ?? "n/a"}; BackupKey: {backupReason ?? "n/a"}";
					}
					this.WriteObject(new TboDpapiMasterKeyInfo
					{
						ServerName = this.ServerName,
						Scope = location.Scope,
						UserSid = location.UserSid,
						KeyPath = location.KeyPath,
						MasterKeyGuid = masterKeyGuid,
						IsPreferred = location.IsPreferred,
						FailureReason = reason
					});
				}
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private (byte[]? MachineKey, byte[]? UserKey) ResolveDpapiKeys()
		{
			var machineKey = (this.DpapiMachineKeyBytes != null && this.DpapiMachineKeyBytes.Length > 0)
				? this.DpapiMachineKeyBytes
				: null;
			var userKey = (this.DpapiUserKeyBytes != null && this.DpapiUserKeyBytes.Length > 0)
				? this.DpapiUserKeyBytes
				: null;

			if (machineKey == null && !string.IsNullOrWhiteSpace(this.DpapiMachineKey))
				machineKey = Titanis.BinaryHelper.ParseHexString(this.DpapiMachineKey.AsSpan());
			if (userKey == null && !string.IsNullOrWhiteSpace(this.DpapiUserKey))
				userKey = Titanis.BinaryHelper.ParseHexString(this.DpapiUserKey.AsSpan());

			return (machineKey, userKey);
		}

	}
}
