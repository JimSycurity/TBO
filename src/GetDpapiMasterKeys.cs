using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Text;
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

		[Parameter]
		public string? UserPassword { get; set; }

		[Parameter]
		public string? UserNtlmHash { get; set; }

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

			var dpapiSystemKeys = ResolveDpapiKeys();
			var hasUserMaterial = !string.IsNullOrWhiteSpace(this.UserPassword) || !string.IsNullOrWhiteSpace(this.UserNtlmHash);
			var hasDpapiSystemMaterial = dpapiSystemKeys.MachineKey != null || dpapiSystemKeys.UserKey != null;

			var effectiveScope = this.Scope;
			if (effectiveScope.HasFlag(DpapiMasterKeyScope.Machine) && !hasDpapiSystemMaterial)
			{
				this.WriteWarning("Get-TBODpapiMasterKeys cannot decrypt machine master keys without DPAPI_SYSTEM. Supply DpapiMachineKey/DpapiUserKey (or pipe Get-TBORegLsaSecrets -Name DPAPI_SYSTEM).");
				effectiveScope &= ~DpapiMasterKeyScope.Machine;
			}

			if (effectiveScope.HasFlag(DpapiMasterKeyScope.User) && !hasDpapiSystemMaterial && !hasUserMaterial)
			{
				this.WriteWarning("Get-TBODpapiMasterKeys cannot decrypt user profile master keys without UserPassword/UserNtlmHash (or DPAPI_SYSTEM).");
				effectiveScope &= ~DpapiMasterKeyScope.User;
			}

			if (effectiveScope == DpapiMasterKeyScope.None)
				return;

			byte[]? userNtHash = null;
			if (!string.IsNullOrWhiteSpace(this.UserNtlmHash))
			{
				try
				{
					userNtHash = NtlmHashInput.Parse(this.UserNtlmHash).NtHash;
				}
				catch (Exception ex)
				{
					throw new ArgumentException($"UserNtlmHash was invalid: {ex.Message}", nameof(this.UserNtlmHash), ex);
				}
			}

			byte[]? userSha1Hash = null;
			byte[]? userNtHashFromPassword = null;
			if (!string.IsNullOrWhiteSpace(this.UserPassword))
			{
				var pwdUtf16 = Encoding.Unicode.GetBytes(this.UserPassword);
				userSha1Hash = SHA1.HashData(pwdUtf16);

				if (userNtHash == null)
				{
					userNtHashFromPassword = Titanis.Crypto.SlimHashAlgorithm
						.ComputeHash<Titanis.Crypto.Md4Context>(pwdUtf16);
				}
			}

			var credHistStartHashes = new List<(string Label, byte[] Hash)>();
			if (userSha1Hash != null && userSha1Hash.Length > 0)
				credHistStartHashes.Add(("SHA1(password)", userSha1Hash));
			if (userNtHash != null && userNtHash.Length > 0)
				credHistStartHashes.Add(("UserNtlmHash", userNtHash));
			if (userNtHashFromPassword != null && userNtHashFromPassword.Length > 0)
				credHistStartHashes.Add(("NT(password)", userNtHashFromPassword));

			credHistStartHashes = credHistStartHashes
				.GroupBy(x => Convert.ToHexString(x.Hash), StringComparer.OrdinalIgnoreCase)
				.Select(g => g.First())
				.ToList();

			var credHistCache = new Dictionary<string, DpapiCredHistFile?>(StringComparer.OrdinalIgnoreCase);
			DpapiCredHistFile? ResolveCredHistFile(string credHistPath)
			{
				if (credHistCache.TryGetValue(credHistPath, out var cached))
					return cached;

				try
				{
					var bytes = DpapiHelpers.ReadFileBytes(smb, UncPath.Parse(credHistPath), cancellationToken);
					var parsed = DpapiCredHistFile.Parse(bytes);
					credHistCache[credHistPath] = parsed;
					return parsed;
				}
				catch (Exception ex)
				{
					this.WriteVerbose($"Get-TBODpapiMasterKeys could not load CREDHIST from {credHistPath}: {ex.Message}");
					credHistCache[credHistPath] = null;
					return null;
				}
			}

			var userKeyCache = new Dictionary<string, IReadOnlyList<DpapiKeyMaterialCandidate>>(StringComparer.OrdinalIgnoreCase);
			IReadOnlyList<DpapiKeyMaterialCandidate> ResolveUserCandidates(string sid)
			{
				if (userKeyCache.TryGetValue(sid, out var cached))
					return cached;

				var derived = DpapiUserKeyDerivation.DerivePreKeyCandidates(
					sid,
					this.UserPassword,
					userNtHash);

				userKeyCache[sid] = derived;
				return derived;
			}

			var locations = DpapiMasterKeyLocator.Enumerate(
				smb,
				serverName,
				shareName,
				effectiveScope,
				message => this.WriteWarning(message),
				null,
				message => this.WriteVerbose(message),
				cancellationToken);

			foreach (var location in locations)
			{
				var keyCandidates = new List<DpapiKeyMaterialCandidate>();
				var isUserScope = location.Scope.Equals("User", StringComparison.OrdinalIgnoreCase);
				var isMachineScope = location.Scope.Equals("Machine", StringComparison.OrdinalIgnoreCase);

				if (isUserScope && hasUserMaterial && !string.IsNullOrWhiteSpace(location.UserSid))
					keyCandidates.AddRange(ResolveUserCandidates(location.UserSid));

				if (isMachineScope)
				{
					if (dpapiSystemKeys.MachineKey != null && dpapiSystemKeys.MachineKey.Length > 0)
					{
						keyCandidates.Add(new DpapiKeyMaterialCandidate
						{
							Label = "DPAPI_SYSTEM: machine key",
							KeyMaterial = dpapiSystemKeys.MachineKey,
							Confidence = 1.0
						});
					}

					if (dpapiSystemKeys.UserKey != null && dpapiSystemKeys.UserKey.Length > 0)
					{
						keyCandidates.Add(new DpapiKeyMaterialCandidate
						{
							Label = "DPAPI_SYSTEM: user key",
							KeyMaterial = dpapiSystemKeys.UserKey,
							Confidence = 1.0
						});
					}
				}
				else
				{
					if (dpapiSystemKeys.UserKey != null && dpapiSystemKeys.UserKey.Length > 0)
					{
						keyCandidates.Add(new DpapiKeyMaterialCandidate
						{
							Label = "DPAPI_SYSTEM: user key",
							KeyMaterial = dpapiSystemKeys.UserKey,
							Confidence = 1.0
						});
					}

					if (dpapiSystemKeys.MachineKey != null && dpapiSystemKeys.MachineKey.Length > 0)
					{
						keyCandidates.Add(new DpapiKeyMaterialCandidate
						{
							Label = "DPAPI_SYSTEM: machine key",
							KeyMaterial = dpapiSystemKeys.MachineKey,
							Confidence = 1.0
						});
					}
				}

				keyCandidates = keyCandidates
					.Where(c => c.KeyMaterial != null && c.KeyMaterial.Length > 0)
					.GroupBy(c => Convert.ToHexString(c.KeyMaterial), StringComparer.OrdinalIgnoreCase)
					.Select(g => g.First())
					.ToList();

				if (keyCandidates.Count == 0)
				{
					var missingReason = isUserScope
						? "No key material available for user master keys. Supply UserPassword/UserNtlmHash (or DPAPI_SYSTEM)."
						: "No key material available for machine master keys. Supply DPAPI_SYSTEM (DpapiMachineKey/DpapiUserKey).";

					this.WriteObject(new TboDpapiMasterKeyInfo
					{
						ServerName = this.ServerName,
						Scope = location.Scope,
						UserSid = location.UserSid,
						KeyPath = location.KeyPath,
						MasterKeyGuid = location.MasterKeyGuid,
						IsPreferred = location.IsPreferred,
						FailureReason = missingReason
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

				DpapiMasterKeyFileDecryptionResult? decryptResult = null;
				DpapiMasterKeyDecryptionResult? bestResult = null;
				string? usedKeyLabel = null;

				bool TryDecryptWithCandidates(IEnumerable<DpapiKeyMaterialCandidate> candidates)
				{
					foreach (var candidate in candidates)
					{
						var candidateResult = masterKeyFile.DecryptWithKey(candidate.KeyMaterial);
						var candidateBest = candidateResult.MasterKeyResult?.Success == true
							? candidateResult.MasterKeyResult
							: candidateResult.BackupKeyResult;

						decryptResult = candidateResult;
						bestResult = candidateBest;
						usedKeyLabel = candidate.Label;

						if (candidateBest?.Success == true)
							return true;
					}

					return false;
				}

				var decrypted = TryDecryptWithCandidates(keyCandidates);
				if (!decrypted
					&& isUserScope
					&& hasUserMaterial
					&& !string.IsNullOrWhiteSpace(location.UserSid)
					&& credHistStartHashes.Count > 0
					&& (masterKeyFile.CredHist != null || masterKeyFile.CredHistLength > 0))
				{
					var keyDir = Path.GetDirectoryName(location.KeyPath);
					if (!string.IsNullOrWhiteSpace(keyDir))
					{
						var credHistPath = Path.Combine(keyDir, "CREDHIST");
						var credHistFile = ResolveCredHistFile(credHistPath);
						if (credHistFile != null)
						{
							var targetGuid = masterKeyFile.CredHist?.Guid;
							var tried = new HashSet<string>(
								keyCandidates.Select(c => Convert.ToHexString(c.KeyMaterial)),
								StringComparer.OrdinalIgnoreCase);

							foreach (var (label, startHash) in credHistStartHashes)
							{
								if (!credHistFile.TryDecryptChain(startHash, out var decryptedEntries, out var failureReason))
								{
									this.WriteVerbose($"Get-TBODpapiMasterKeys failed to decrypt CREDHIST ({label}) for {location.KeyPath}: {failureReason}");
									continue;
								}

								var candidatesToUse = decryptedEntries;
								if (targetGuid.HasValue)
								{
									var match = decryptedEntries.FirstOrDefault(e => e.Guid == targetGuid.Value);
									if (match != null)
										candidatesToUse = new[] { match };
								}

								var credCandidates = new List<DpapiKeyMaterialCandidate>();
								foreach (var entry in candidatesToUse)
								{
									if (entry.PasswordHash != null && entry.PasswordHash.Length > 0)
									{
										credCandidates.Add(new DpapiKeyMaterialCandidate
										{
											Label = $"CREDHIST {entry.Guid}: HMAC-SHA1(pwdhash, SID)",
											KeyMaterial = DpapiUserKeyDerivation.DeriveLocalPreKeyFromHash(location.UserSid, entry.PasswordHash),
											Confidence = 0.8
										});
									}

									if (entry.NtHash != null && entry.NtHash.Length == 16)
									{
										credCandidates.Add(new DpapiKeyMaterialCandidate
										{
											Label = $"CREDHIST {entry.Guid}: HMAC-SHA1(PBKDF2-SHA256(NT), SID)",
											KeyMaterial = DpapiUserKeyDerivation.DeriveDomainPreKeyFromNtHash(location.UserSid, entry.NtHash),
											Confidence = 0.7
										});

										credCandidates.Add(new DpapiKeyMaterialCandidate
										{
											Label = $"CREDHIST {entry.Guid}: HMAC-SHA1(NT, SID)",
											KeyMaterial = DpapiUserKeyDerivation.DeriveFallbackPreKeyFromNtHash(location.UserSid, entry.NtHash),
											Confidence = 0.4
										});
									}
								}

								credCandidates = credCandidates
									.Where(c => c.KeyMaterial != null && c.KeyMaterial.Length > 0)
									.Where(c => tried.Add(Convert.ToHexString(c.KeyMaterial)))
									.OrderByDescending(c => c.Confidence)
									.ThenBy(c => c.Label, StringComparer.OrdinalIgnoreCase)
									.ToList();

								if (credCandidates.Count == 0)
									continue;

								this.WriteVerbose($"Get-TBODpapiMasterKeys attempting CREDHIST-based decryption ({label}) for {location.KeyPath}.");
								decrypted = TryDecryptWithCandidates(credCandidates);
								if (decrypted)
									break;
							}
						}
					}
				}

				if (bestResult != null && bestResult.Success && bestResult.MasterKey != null)
				{
					if (!string.IsNullOrWhiteSpace(usedKeyLabel))
						this.WriteVerbose($"Get-TBODpapiMasterKeys decrypted {location.KeyPath} using {usedKeyLabel}.");

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
					var masterReason = decryptResult?.MasterKeyResult?.FailureReason;
					var backupReason = decryptResult?.BackupKeyResult?.FailureReason;
					var reason = bestResult?.FailureReason ?? decryptResult?.FailureReason ?? "Failed to decrypt master key.";
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
