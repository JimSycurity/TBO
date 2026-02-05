using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegLsaSecretInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Name { get; init; } = string.Empty;
		public string KeyPath { get; init; } = string.Empty;
		public DateTime? LastWriteTime { get; init; }
		public string? Secret { get; init; }
		public string? DpapiMachineKey { get; init; }
		public string? DpapiUserKey { get; init; }
		public byte[]? SecretBytes { get; init; }
		public byte[]? SecretRawBytes { get; init; }
		public byte[]? EncryptedBytes { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegLsaSecrets")]
	[OutputType(typeof(TboRegLsaSecretInfo))]
	public sealed class GetTBORegLsaSecrets : TboRegLsaSecretCmdlet
	{
		[Parameter(Position = 1)]
		public string[]? Name { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public byte[]? LsaKeyBytes { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public string? LsaKey { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				var lsaKey = ResolveLsaKey(
					smb,
					session.Client,
					cancellationToken,
					this.LsaKeyBytes,
					this.LsaKey,
					nameof(this.LsaKey),
					out _);
				if (lsaKey == null || lsaKey.Length == 0)
				{
					this.LogWarning(smb, "Get-TBORegLsaSecrets failed to derive the LSA key.");
					return;
				}

				var names = ResolveSecretNames(session.Client, cancellationToken);
				if (names.Count == 0)
					return;

				var filters = BuildNameFilters(this.Name);
				foreach (var name in names)
				{
					if (!MatchesAny(filters, name))
						continue;

					DateTime? lastWriteTime;
					var secretBlob = TryReadSecretValue(session.Client, name, "CurrVal", cancellationToken, out lastWriteTime);
					if (secretBlob == null || secretBlob.Length == 0)
					{
						this.LogWarning(smb, $"Get-TBORegLsaSecrets failed to read secret '{name}': value is empty.");
						continue;
					}

					var decrypted = DecryptLsaSecret(secretBlob, lsaKey);
					if (decrypted == null || decrypted.Length == 0)
					{
						this.LogWarning(smb, $"Get-TBORegLsaSecrets failed to decrypt secret '{name}': data was empty.");
						continue;
					}

					byte[]? payload = null;
					string? secretText = null;
					string? dpapiMachineKey = null;
					string? dpapiUserKey = null;
					if (TryExtractSecretPayload(decrypted, out var payloadBytes))
					{
						payload = payloadBytes;
						secretText = FormatSecretText(name, payloadBytes, TryDecodeSecretString(payloadBytes));
						if (TrySplitDpapiSecret(name, payloadBytes, out var machineKey, out var userKey))
						{
							dpapiMachineKey = machineKey;
							dpapiUserKey = userKey;
						}
					}

					var keyPath = $"HKEY_LOCAL_MACHINE\\{SecretsPath}\\{name}\\CurrVal";
					this.WriteObject(new TboRegLsaSecretInfo
					{
						ServerName = this.ServerName,
						Name = name,
						KeyPath = keyPath,
						LastWriteTime = lastWriteTime,
						Secret = secretText,
						DpapiMachineKey = dpapiMachineKey,
						DpapiUserKey = dpapiUserKey,
						SecretBytes = payload,
						SecretRawBytes = decrypted,
						EncryptedBytes = secretBlob
					});
				}
			});
		}

		private List<string> ResolveSecretNames(IRegistryClient client, CancellationToken cancellationToken)
		{
			if (this.Name != null && this.Name.Length > 0 && this.Name.All(n => !string.IsNullOrWhiteSpace(n)) && !HasWildcardNames())
				return this.Name.Where(n => !string.IsNullOrWhiteSpace(n)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

			var secretsSpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				SecretsPath);

			using var secretsKey = OpenRegistryKey(client, secretsSpec, RegistryAccessRights.EnumerateSubkeys, cancellationToken);
			return CollectSubkeys(secretsKey, cancellationToken)
				.Select(r => r.KeyName)
				.Where(name => !string.IsNullOrWhiteSpace(name))
				.ToList();
		}

		private bool HasWildcardNames()
		{
			if (this.Name == null)
				return false;

			foreach (var name in this.Name)
			{
				if (!string.IsNullOrWhiteSpace(name) && WildcardPattern.ContainsWildcardCharacters(name))
					return true;
			}

			return false;
		}

	}
}
