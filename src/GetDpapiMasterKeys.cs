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

		/// <summary>
		/// When set, persists successful DPAPI decryption artifacts to the TBO cache:
		/// 1) verified password/NT hashes to <c>verified_password_hashes</c> (for candidate reuse),
		/// 2) recovered master key cleartext to <c>dpapi_masterkeys.cleartext_key</c>.
		/// Cache reads are always attempted when cache ingestion is enabled — see
		/// <c>ResolveCacheIngestionEnabled</c>.
		/// </summary>
		[Parameter]
		public SwitchParameter Cache { get; set; }

		/// <summary>
		/// Optional explicit path to the TBO cache SQLite file. Overrides the
		/// <c>TITANIS_TBO_CACHE</c> environment variable and the default per-user path.
		/// </summary>
		[Parameter]
		public string? CachePath { get; set; }

		/// <summary>Name used as <c>verified_by_cmdlet</c> provenance in the cache.</summary>
		private const string CacheCmdletName = "Get-TBODpapiMasterKeys";
		private const string VerifiedViaDirect = "masterkey_direct_decrypt";
		private const string VerifiedViaCredHist = "credhist_chain_decrypt";
		private const string CacheCredentialDpapiSystemMachineKey = "DPAPI_SYSTEM_MACHINE_KEY";
		private const string CacheCredentialDpapiSystemUserKey = "DPAPI_SYSTEM_USER_KEY";

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

			// Load any cache-backed password/NT material for this server (verified hashes plus
			// SID-correlated credential observations such as Get-TBORegSamHashes NTHash entries).
			// Keyed by user SID so ResolveUserCandidates can fold them into the candidate list.
			var cacheIngestEnabled = this.ResolveCacheIngestionEnabled(this.Cache);
			if (cacheIngestEnabled)
			{
				var machineKey = dpapiSystemKeys.MachineKey;
				var userKey = dpapiSystemKeys.UserKey;
				TryLoadDpapiSystemKeysFromCache(serverName, ref machineKey, ref userKey);
				dpapiSystemKeys = (machineKey, userKey);
			}

			var hasPlaintextUserMaterial = !string.IsNullOrWhiteSpace(this.UserPassword) || !string.IsNullOrWhiteSpace(this.UserNtlmHash);
			var hasDpapiSystemMaterial = dpapiSystemKeys.MachineKey != null || dpapiSystemKeys.UserKey != null;

			var cachedHashesBySid = new Dictionary<string, (byte[]? Sha1Pwd, byte[]? NtPwd)>(StringComparer.OrdinalIgnoreCase);
			if (cacheIngestEnabled)
			{
				LoadCachedHashes(serverName, cachedHashesBySid);
			}
			var hasCachedUserMaterial = cachedHashesBySid.Count > 0;
			var hasUserMaterial = hasPlaintextUserMaterial || hasCachedUserMaterial;

			var effectiveScope = this.Scope;
			if (effectiveScope.HasFlag(DpapiMasterKeyScope.Machine) && !hasDpapiSystemMaterial)
			{
				this.WriteWarning("Get-TBODpapiMasterKeys cannot decrypt machine master keys without DPAPI_SYSTEM. Supply DpapiMachineKey/DpapiUserKey (or pipe Get-TBORegLsaSecrets -Name DPAPI_SYSTEM).");
				effectiveScope &= ~DpapiMasterKeyScope.Machine;
			}

			if (effectiveScope.HasFlag(DpapiMasterKeyScope.User) && !hasDpapiSystemMaterial && !hasUserMaterial)
			{
				this.WriteWarning("Get-TBODpapiMasterKeys cannot decrypt user profile master keys without UserPassword/UserNtlmHash (or DPAPI_SYSTEM, or cache-backed SID hash material).");
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

			// (Label, Hash, HashType) — HashType matches DpapiVerifiedHashTypes constants so that a
			// successful CREDHIST chain decrypt can attribute the winning start-hash back to its
			// verified kind when caching. Cached hashes get folded in per-SID inside the loop below.
			var credHistStartHashes = new List<(string Label, byte[] Hash, string HashType)>();
			if (userSha1Hash != null && userSha1Hash.Length > 0)
				credHistStartHashes.Add(("SHA1(password)", userSha1Hash, DpapiVerifiedHashTypes.Sha1Pwd));
			if (userNtHash != null && userNtHash.Length > 0)
				credHistStartHashes.Add(("UserNtlmHash", userNtHash, DpapiVerifiedHashTypes.NtPwd));
			if (userNtHashFromPassword != null && userNtHashFromPassword.Length > 0)
				credHistStartHashes.Add(("NT(password)", userNtHashFromPassword, DpapiVerifiedHashTypes.NtPwd));

			credHistStartHashes = credHistStartHashes
				.GroupBy(x => x.HashType + ":" + Convert.ToHexString(x.Hash), StringComparer.OrdinalIgnoreCase)
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

				// Start from plaintext material (if supplied): this produces candidates tagged with
				// SourceHashType/SourceHash so a successful decrypt can be written back to cache.
				var combined = new List<DpapiKeyMaterialCandidate>();
				combined.AddRange(DpapiUserKeyDerivation.DerivePreKeyCandidates(
					sid,
					this.UserPassword,
					userNtHash));

				// Fold in any cached verified hashes for this SID. Same source-hash → same prekey →
				// Deduplicate() drops the duplicate, so plaintext and cache coexist without double work.
				if (cachedHashesBySid.TryGetValue(sid, out var cachedForSid))
				{
					var fromCache = DpapiUserKeyDerivation.DerivePreKeyCandidatesFromHashes(
						sid,
						cachedForSid.Sha1Pwd,
						cachedForSid.NtPwd);
					if (fromCache.Count > 0)
					{
						this.WriteVerbose($"Get-TBODpapiMasterKeys: loaded {fromCache.Count} cached hash candidate(s) for SID {sid}.");
						combined.AddRange(fromCache);
					}
				}

				// Deduplicate by prekey bytes (not by source hash) so that identical prekeys reached
				// via different paths collapse to one attempt.
				var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
				var deduped = new List<DpapiKeyMaterialCandidate>(combined.Count);
				foreach (var cand in combined)
				{
					if (cand.KeyMaterial == null || cand.KeyMaterial.Length == 0)
						continue;
					if (!seen.Add(Convert.ToHexString(cand.KeyMaterial)))
						continue;
					deduped.Add(cand);
				}

				IReadOnlyList<DpapiKeyMaterialCandidate> derived = deduped;
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

					if (!string.IsNullOrWhiteSpace(location.UserSid)
						&& dpapiSystemKeys.UserKey != null
						&& dpapiSystemKeys.UserKey.Length > 0)
					{
						// Service/virtual-account style DPAPI can use a SID-derived prekey from
						// DPAPI_SYSTEM user key material.
						keyCandidates.Add(new DpapiKeyMaterialCandidate
						{
							Label = "DPAPI_SYSTEM: HMAC-SHA1(user key, SID)",
							KeyMaterial = DpapiUserKeyDerivation.DeriveLocalPreKeyFromHash(location.UserSid, dpapiSystemKeys.UserKey),
							Confidence = 0.95
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
				DpapiKeyMaterialCandidate? usedKeyCandidate = null;

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
						usedKeyCandidate = candidate;

						if (candidateBest?.Success == true)
							return true;
					}

					return false;
				}

				var decrypted = TryDecryptWithCandidates(keyCandidates);
				var decryptedViaCredHist = false;

				// Per-SID CREDHIST start-hash list: base list (plaintext-derived) plus any cached
				// hashes known for this particular user. The cache may contain hashes for users we
				// never saw plaintext material for, which is precisely why this feature exists.
				var perSidCredHistStartHashes = credHistStartHashes;
				if (isUserScope && !string.IsNullOrWhiteSpace(location.UserSid)
					&& cachedHashesBySid.TryGetValue(location.UserSid, out var cachedForCredHist))
				{
					var list = new List<(string Label, byte[] Hash, string HashType)>(credHistStartHashes);
					if (cachedForCredHist.Sha1Pwd != null && cachedForCredHist.Sha1Pwd.Length > 0)
						list.Add(("cache:sha1_pwd", cachedForCredHist.Sha1Pwd, DpapiVerifiedHashTypes.Sha1Pwd));
					if (cachedForCredHist.NtPwd != null && cachedForCredHist.NtPwd.Length > 0)
						list.Add(("cache:nt_pwd", cachedForCredHist.NtPwd, DpapiVerifiedHashTypes.NtPwd));

					perSidCredHistStartHashes = list
						.GroupBy(x => x.HashType + ":" + Convert.ToHexString(x.Hash), StringComparer.OrdinalIgnoreCase)
						.Select(g => g.First())
						.ToList();
				}

				if (!decrypted
					&& isUserScope
					&& hasUserMaterial
					&& !string.IsNullOrWhiteSpace(location.UserSid)
					&& perSidCredHistStartHashes.Count > 0
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

							foreach (var (label, startHash, _) in perSidCredHistStartHashes)
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
									// Historical CREDHIST entries are also verified-by-decrypt: if one
									// of these prekeys wins, we cache the originating SHA1/NT hash so
									// future cmdlet runs can reuse it without re-deriving CREDHIST.
									if (entry.PasswordHash != null && entry.PasswordHash.Length > 0)
									{
										credCandidates.Add(new DpapiKeyMaterialCandidate
										{
											Label = $"CREDHIST {entry.Guid}: HMAC-SHA1(pwdhash, SID\\0)",
											KeyMaterial = DpapiUserKeyDerivation.DeriveLocalPreKeyFromHash(location.UserSid, entry.PasswordHash),
											Confidence = 0.8,
											SourceHashType = DpapiVerifiedHashTypes.Sha1Pwd,
											SourceHash = (byte[])entry.PasswordHash.Clone(),
										});

										credCandidates.Add(new DpapiKeyMaterialCandidate
										{
											Label = $"CREDHIST {entry.Guid}: HMAC-SHA1(pwdhash, SID)",
											KeyMaterial = DpapiUserKeyDerivation.DeriveLocalPreKeyFromHashNoTerminator(location.UserSid, entry.PasswordHash),
											Confidence = 0.75,
											SourceHashType = DpapiVerifiedHashTypes.Sha1Pwd,
											SourceHash = (byte[])entry.PasswordHash.Clone(),
										});
									}

									if (entry.NtHash != null && entry.NtHash.Length == 16)
									{
										credCandidates.Add(new DpapiKeyMaterialCandidate
										{
											Label = $"CREDHIST {entry.Guid}: HMAC-SHA1(SHA1(NT), SID\\0)",
											KeyMaterial = DpapiUserKeyDerivation.DeriveLocalPreKeyFromNtHash(location.UserSid, entry.NtHash),
											Confidence = 0.75,
											SourceHashType = DpapiVerifiedHashTypes.NtPwd,
											SourceHash = (byte[])entry.NtHash.Clone(),
										});

										credCandidates.Add(new DpapiKeyMaterialCandidate
										{
											Label = $"CREDHIST {entry.Guid}: HMAC-SHA1(SHA1(NT), SID)",
											KeyMaterial = DpapiUserKeyDerivation.DeriveLocalPreKeyFromNtHashNoTerminator(location.UserSid, entry.NtHash),
											Confidence = 0.7,
											SourceHashType = DpapiVerifiedHashTypes.NtPwd,
											SourceHash = (byte[])entry.NtHash.Clone(),
										});

										credCandidates.Add(new DpapiKeyMaterialCandidate
										{
											Label = $"CREDHIST {entry.Guid}: HMAC-SHA1(PBKDF2-SHA256(NT), SID)",
											KeyMaterial = DpapiUserKeyDerivation.DeriveDomainPreKeyFromNtHash(location.UserSid, entry.NtHash),
											Confidence = 0.7,
											SourceHashType = DpapiVerifiedHashTypes.NtPwd,
											SourceHash = (byte[])entry.NtHash.Clone(),
										});

										credCandidates.Add(new DpapiKeyMaterialCandidate
										{
											Label = $"CREDHIST {entry.Guid}: HMAC-SHA1(NT, SID\\0)",
											KeyMaterial = DpapiUserKeyDerivation.DeriveFallbackPreKeyFromNtHash(location.UserSid, entry.NtHash),
											Confidence = 0.4,
											SourceHashType = DpapiVerifiedHashTypes.NtPwd,
											SourceHash = (byte[])entry.NtHash.Clone(),
										});

										credCandidates.Add(new DpapiKeyMaterialCandidate
										{
											Label = $"CREDHIST {entry.Guid}: HMAC-SHA1(NT, SID)",
											KeyMaterial = DpapiUserKeyDerivation.DeriveFallbackPreKeyFromNtHashNoTerminator(location.UserSid, entry.NtHash),
											Confidence = 0.35,
											SourceHashType = DpapiVerifiedHashTypes.NtPwd,
											SourceHash = (byte[])entry.NtHash.Clone(),
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
								{
									decryptedViaCredHist = true;
									break;
								}
							}
						}
					}
				}

				if (bestResult != null && bestResult.Success && bestResult.MasterKey != null)
				{
					if (!string.IsNullOrWhiteSpace(usedKeyCandidate?.Label))
						this.WriteVerbose($"Get-TBODpapiMasterKeys decrypted {location.KeyPath} using {usedKeyCandidate.Label}.");

					if (!string.IsNullOrWhiteSpace(masterKeyGuid)
						&& Guid.TryParse(masterKeyGuid, out var parsedMasterKeyGuid))
					{
						TboDpapiMasterKeyCache.TrySet(smb, serverName, parsedMasterKeyGuid, bestResult.MasterKey);
					}

					if (cacheIngestEnabled
						&& !string.IsNullOrWhiteSpace(masterKeyGuid))
					{
						WriteDecryptedMasterKeyToCache(
							serverName: serverName,
							scope: location.Scope,
							userSid: location.UserSid,
							keyPath: location.KeyPath,
							masterKeyGuid: masterKeyGuid!,
							isPreferred: location.IsPreferred,
							masterKeyBytes: bestResult.MasterKey,
							masterKeyHashBytes: bestResult.MasterKeyHash);
					}

					// Persist the source hash that just verified to the verified-hash cache so that
					// subsequent cmdlet runs (including the planned Invoke-TBOTriage cmdlet — TBO-txp)
					// can reuse it without asking for the plaintext password again. Only candidates
					// carrying both a SourceHashType and SourceHash qualify; DPAPI_SYSTEM-derived
					// prekeys and other opaque material are intentionally not cached.
					if (cacheIngestEnabled
						&& isUserScope
						&& !string.IsNullOrWhiteSpace(location.UserSid)
						&& usedKeyCandidate?.SourceHashType != null
						&& usedKeyCandidate.SourceHash != null
						&& usedKeyCandidate.SourceHash.Length > 0)
					{
						WriteVerifiedHashToCache(
							serverName,
							location.UserSid!,
							usedKeyCandidate.SourceHashType,
							usedKeyCandidate.SourceHash,
							verifiedVia: decryptedViaCredHist ? VerifiedViaCredHist : VerifiedViaDirect,
							contextForErrors: location.KeyPath);
					}

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

		/// <summary>
		/// Reads cache-backed password hash material for <paramref name="serverName"/> and populates
		/// <paramref name="target"/> keyed by user SID. Data sources:
		/// 1) <c>verified_password_hashes</c> (cryptographically verified hashes)
		/// 2) SID-linked <c>NTHash</c> observations from the graph tables (for example, Get-TBORegSamHashes)
		/// Failures are logged and swallowed — cache reads must never break the cmdlet.
		/// </summary>
		private void TryLoadDpapiSystemKeysFromCache(string serverName, ref byte[]? machineKey, ref byte[]? userKey)
		{
			if (!string.IsNullOrWhiteSpace(this.DpapiMachineKey)
				|| (this.DpapiMachineKeyBytes != null && this.DpapiMachineKeyBytes.Length > 0))
			{
				// Explicit machine key input takes precedence over cache material.
			}
			else if (machineKey == null || machineKey.Length == 0)
			{
				TryLoadSingleCachedCredential(serverName, CacheCredentialDpapiSystemMachineKey, out machineKey);
			}

			if (!string.IsNullOrWhiteSpace(this.DpapiUserKey)
				|| (this.DpapiUserKeyBytes != null && this.DpapiUserKeyBytes.Length > 0))
			{
				// Explicit user key input takes precedence over cache material.
			}
			else if (userKey == null || userKey.Length == 0)
			{
				TryLoadSingleCachedCredential(serverName, CacheCredentialDpapiSystemUserKey, out userKey);
			}
		}

		private void TryLoadSingleCachedCredential(string serverName, string credentialKind, out byte[]? keyBytes)
		{
			keyBytes = null;

			TboCacheDatabase? cacheDb = null;
			try
			{
				cacheDb = TboCacheDatabase.Open(this.CachePath, msg => this.WriteVerbose(msg));
				var identifiers = cacheDb.QueryObservedCredentialIdentifiers(serverName, credentialKind, maxCount: 1);
				if (identifiers.Count == 0)
					return;

				var hex = identifiers[0];
				if (string.IsNullOrWhiteSpace(hex))
					return;

				keyBytes = Titanis.BinaryHelper.ParseHexString(hex.AsSpan());
				if (keyBytes == null || keyBytes.Length == 0)
				{
					keyBytes = null;
					return;
				}

				this.WriteVerbose($"Get-TBODpapiMasterKeys: loaded {credentialKind} from cache for {serverName}.");
			}
			catch (Exception ex)
			{
				this.WriteVerbose($"Get-TBODpapiMasterKeys: could not load {credentialKind} from cache for {serverName}: {ex.Message}");
				keyBytes = null;
			}
			finally
			{
				cacheDb?.Dispose();
			}
		}

		private void LoadCachedHashes(string serverName, Dictionary<string, (byte[]? Sha1Pwd, byte[]? NtPwd)> target)
		{
			TboCacheDatabase? cacheDb = null;
			try
			{
				cacheDb = TboCacheDatabase.Open(this.CachePath, msg => this.WriteVerbose(msg));
				var rows = cacheDb.QueryVerifiedPasswordHashes(serverName, userSid: null);
				foreach (var row in rows)
				{
					byte[]? parsed;
					try
					{
						parsed = Convert.FromHexString(row.HashValueHex);
					}
					catch (FormatException ex)
					{
						this.WriteVerbose($"Get-TBODpapiMasterKeys: skipping malformed cached hash for {row.UserSid} ({row.HashType}): {ex.Message}");
						continue;
					}

					if (!target.TryGetValue(row.UserSid, out var existing))
						existing = (null, null);

					switch (row.HashType)
					{
						case DpapiVerifiedHashTypes.Sha1Pwd:
							if (existing.Sha1Pwd == null)
								existing = (parsed, existing.NtPwd);
							break;
						case DpapiVerifiedHashTypes.NtPwd:
							if (existing.NtPwd == null)
								existing = (existing.Sha1Pwd, parsed);
							break;
						default:
							this.WriteVerbose($"Get-TBODpapiMasterKeys: skipping unknown cached hash type '{row.HashType}' for SID {row.UserSid}.");
							continue;
					}

					target[row.UserSid] = existing;
				}

				// Fall back to SID-correlated graph observations (for example, Get-TBORegSamHashes
				// NTHash entries) when no verified NT hash exists for a SID yet.
				var observedRows = cacheDb.QueryObservedNtlmHashes(serverName, userSid: null);
				var observedSidCount = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
				foreach (var row in observedRows)
				{
					if (string.IsNullOrWhiteSpace(row.UserSid) || string.IsNullOrWhiteSpace(row.HashValue))
						continue;

					byte[] ntHash;
					try
					{
						ntHash = NtlmHashInput.Parse(row.HashValue).NtHash;
					}
					catch (Exception ex)
					{
						this.WriteVerbose($"Get-TBODpapiMasterKeys: skipping malformed observed NTHash for {row.UserSid} from {row.SourceKind}: {ex.Message}");
						continue;
					}

					if (ntHash == null || ntHash.Length == 0)
						continue;

					if (!target.TryGetValue(row.UserSid, out var existing))
						existing = (null, null);

					if (existing.NtPwd != null && existing.NtPwd.Length > 0)
						continue;

					existing = (existing.Sha1Pwd, ntHash);
					target[row.UserSid] = existing;
					observedSidCount.Add(row.UserSid);
				}

				if (target.Count > 0)
					this.WriteVerbose($"Get-TBODpapiMasterKeys: loaded cached hash material for {target.Count} SID(s) on {serverName}.");
				if (observedSidCount.Count > 0)
					this.WriteVerbose($"Get-TBODpapiMasterKeys: loaded SID-correlated observed NTHash candidates for {observedSidCount.Count} SID(s) on {serverName}.");
			}
			catch (Exception ex)
			{
				this.WriteWarning($"Get-TBODpapiMasterKeys: cache read failed for {serverName}: {ex.Message}");
			}
			finally
			{
				cacheDb?.Dispose();
			}
		}

		/// <summary>
		/// Persists a verified password/NT hash to the TBO cache. Failures are logged and swallowed.
		/// </summary>
		private void WriteVerifiedHashToCache(
			string serverName,
			string userSid,
			string hashType,
			byte[] hashBytes,
			string verifiedVia,
			string contextForErrors)
		{
			TboCacheDatabase? cacheDb = null;
			try
			{
				cacheDb = TboCacheDatabase.Open(this.CachePath, msg => this.WriteVerbose(msg));
				var machineId = cacheDb.UpsertMachine(serverName);
				var hex = Convert.ToHexString(hashBytes);
				cacheDb.UpsertVerifiedPasswordHash(
					machineId: machineId,
					serverName: serverName,
					userSid: userSid,
					userName: null,
					hashType: hashType,
					hashValueHex: hex,
					verifiedByCmdlet: CacheCmdletName,
					verifiedVia: verifiedVia);
				this.WriteVerbose($"Get-TBODpapiMasterKeys: cached verified {hashType} for SID {userSid} on {serverName} (via {verifiedVia}).");
			}
			catch (Exception ex)
			{
				this.WriteWarning($"Get-TBODpapiMasterKeys: cache write failed for {contextForErrors}: {ex.Message}");
			}
			finally
			{
				cacheDb?.Dispose();
			}
		}

		/// <summary>
		/// Persists a recovered cleartext master key to the DPAPI master-key cache table.
		/// Failures are logged and swallowed.
		/// </summary>
		private void WriteDecryptedMasterKeyToCache(
			string serverName,
			string scope,
			string? userSid,
			string keyPath,
			string masterKeyGuid,
			bool isPreferred,
			byte[] masterKeyBytes,
			byte[]? masterKeyHashBytes)
		{
			if (string.IsNullOrWhiteSpace(serverName)
				|| string.IsNullOrWhiteSpace(masterKeyGuid)
				|| masterKeyBytes == null
				|| masterKeyBytes.Length == 0)
			{
				return;
			}

			TboCacheDatabase? cacheDb = null;
			try
			{
				cacheDb = TboCacheDatabase.Open(this.CachePath, msg => this.WriteVerbose(msg));
				var machineId = cacheDb.UpsertMachine(serverName);
				var masterKeyHashHex = (masterKeyHashBytes != null && masterKeyHashBytes.Length > 0)
					? masterKeyHashBytes.ToHexString()
					: SHA1.HashData(masterKeyBytes).ToHexString();

				cacheDb.UpsertDpapiMasterKey(
					machineId: machineId,
					scope: scope,
					userSid: userSid,
					keyPath: keyPath,
					masterKeyGuid: masterKeyGuid,
					isPreferred: isPreferred,
					isDomain: null,
					hashContext: null,
					hash: null,
					hashLine: null,
					failureReason: null,
					cleartextKey: masterKeyBytes,
					cleartextKeySha1: masterKeyHashHex);
			}
			catch (Exception ex)
			{
				this.WriteWarning($"Get-TBODpapiMasterKeys: cache write failed for decrypted master key {masterKeyGuid}: {ex.Message}");
			}
			finally
			{
				cacheDb?.Dispose();
			}
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
