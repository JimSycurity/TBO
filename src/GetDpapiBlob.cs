using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;
using Titanis.Net;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboDpapiBlobDecryptionInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Source { get; init; } = string.Empty;
		public string? Path { get; init; }
		public string? ValueName { get; init; }
		public int Offset { get; init; }
		public string? CredentialGuid { get; init; }
		public string? MasterKeyGuid { get; init; }
		public uint Flags { get; init; }
		public string? Description { get; init; }
		public uint CryptAlgorithmId { get; init; }
		public string? CryptAlgorithm { get; init; }
		public uint HashAlgorithmId { get; init; }
		public string? HashAlgorithm { get; init; }
		public string? Cleartext { get; init; }
		public string? CleartextHex { get; init; }
		public byte[]? CleartextBytes { get; init; }
		public bool HmacValidated { get; init; }
		public string? FailureReason { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBODpapiBlob", DefaultParameterSetName = FileParameterSet)]
	[OutputType(typeof(TboDpapiBlobDecryptionInfo))]
	public sealed class GetTBODpapiBlob : TboRegCmdlet
	{
		private const string CacheSourceKind = "Get-TBODpapiBlob";

		private const string InputObjectParameterSet = "InputObject";
		private const string FileParameterSet = "File";
		private const string RegistryParameterSet = "Registry";
		private const string BytesParameterSet = "Bytes";
		private const string HexParameterSet = "Hex";
		private const string Base64ParameterSet = "Base64";

		[Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = InputObjectParameterSet)]
		public TboDpapiBlobInfo? InputObject { get; set; }

		[Parameter(Mandatory = true, Position = 1, ParameterSetName = FileParameterSet, ValueFromPipelineByPropertyName = true)]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 1, ParameterSetName = RegistryParameterSet, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string RegistryPath { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 2, ParameterSetName = RegistryParameterSet, ValueFromPipelineByPropertyName = true)]
		public string ValueName { get; set; } = string.Empty;

		[Parameter(Mandatory = true, ParameterSetName = BytesParameterSet)]
		public byte[]? BlobBytes { get; set; }

		[Parameter(Mandatory = true, ParameterSetName = HexParameterSet)]
		public string? BlobHex { get; set; }

		[Parameter(Mandatory = true, ParameterSetName = Base64ParameterSet)]
		public string? BlobBase64 { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		[Alias("MatchOffset")]
		public int Offset { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public string? MasterKey { get; set; }

		[Parameter]
		public byte[]? MasterKeyBytes { get; set; }

		[Parameter]
		public string? Entropy { get; set; }

		[Parameter]
		public byte[]? EntropyBytes { get; set; }

		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var explicitMasterKey = ResolveMasterKey();
			if ((this.MasterKeyBytes != null || !string.IsNullOrWhiteSpace(this.MasterKey))
				&& (explicitMasterKey == null || explicitMasterKey.Length == 0))
			{
				throw new ArgumentException("MasterKey must be provided (hex) or MasterKeyBytes must be set.", nameof(this.MasterKey));
			}

			var cacheEnabled = this.ResolveCacheIngestionEnabled(this.Cache);
			var serverName = DpapiHelpers.NormalizeServerName(this.ServerName);
			if (cacheEnabled && string.IsNullOrWhiteSpace(serverName))
			{
				this.LogWarning(smb, "Get-TBODpapiBlob cache read/write disabled: ServerName is required for cache operations.");
				cacheEnabled = false;
			}

			if ((explicitMasterKey == null || explicitMasterKey.Length == 0) && !cacheEnabled)
			{
				throw new ArgumentException(
					"MasterKey must be provided (hex) or MasterKeyBytes must be set. Enable -Cache (or TITANIS_TBO_CACHE_INGEST) to resolve master keys from cache.",
					nameof(this.MasterKey));
			}

			var cachedMasterKeys = cacheEnabled
				? DpapiHelpers.LoadCachedMasterKeys(this.CachePath, serverName, msg => this.LogVerbose(smb, msg), msg => this.LogWarning(smb, msg))
				: new System.Collections.Generic.Dictionary<Guid, byte[]>();
			if (cacheEnabled && cachedMasterKeys.Count > 0)
				TboDpapiMasterKeyCache.TrySetMany(smb, serverName, cachedMasterKeys);

			var entropy = ResolveEntropy();
			TboCacheDatabase? cacheDb = null;
			long cacheMachineId = 0;
			if (cacheEnabled)
			{
				try
				{
					cacheDb = TboCacheDatabase.Open(this.CachePath, msg => this.WriteVerbose(msg));
					cacheMachineId = cacheDb.UpsertMachine(serverName);
				}
				catch (Exception ex)
				{
					cacheDb?.Dispose();
					cacheDb = null;
					cacheMachineId = 0;
					this.LogException(smb, $"Get-TBODpapiBlob failed to open cache DB for {serverName}", ex, emitWarning: false);
					this.LogWarning(smb, $"Get-TBODpapiBlob cache write disabled: {ex.Message}");
				}
			}

			try
			{
				DpapiBlobInput input;
				try
				{
					input = ResolveInput(smb, cancellationToken);
				}
				catch (Exception ex)
				{
					this.WriteObject(new TboDpapiBlobDecryptionInfo
					{
						ServerName = this.ServerName,
						Source = this.ParameterSetName,
						FailureReason = ex.Message
					});
					return;
				}

				DpapiBlob blob;
				try
				{
					blob = DpapiBlob.Parse(input.Data, input.Offset);
				}
				catch (Exception ex)
				{
					var parseFailure = $"Failed to parse DPAPI blob: {ex.Message}";
					TryWriteBlobRecordToCache(smb, cacheDb, cacheMachineId, input, null, parseFailure);
					this.WriteObject(new TboDpapiBlobDecryptionInfo
					{
						ServerName = this.ServerName,
						Source = input.Source,
						Path = input.Path,
						ValueName = input.ValueName,
						Offset = input.Offset,
						FailureReason = parseFailure
					});
					return;
				}

				var masterKey = explicitMasterKey;
				if ((masterKey == null || masterKey.Length == 0) && cacheEnabled)
				{
					if (!cachedMasterKeys.TryGetValue(blob.GuidMasterKey, out masterKey) || masterKey == null || masterKey.Length == 0)
					{
						if (!TboDpapiMasterKeyCache.TryGet(smb, serverName, blob.GuidMasterKey, out masterKey) || masterKey == null || masterKey.Length == 0)
							masterKey = null;
					}
				}

				DpapiBlobDecryptionResult decryptResult;
				if (masterKey == null || masterKey.Length == 0)
				{
					var missingReason = BuildMissingMasterKeyFailureReason(cacheDb, cacheMachineId, blob.GuidMasterKey);
					decryptResult = new DpapiBlobDecryptionResult
					{
						Success = false,
						FailureReason = missingReason
					};
					TryRecordMissingMasterKeyTarget(smb, cacheDb, cacheMachineId, input, blob, missingReason);
				}
				else
				{
					decryptResult = DpapiBlobCrypto.Decrypt(blob, masterKey, entropy);
					if (ShouldTryKnownCngEntropyFallback(input, entropy, decryptResult))
					{
						foreach (var (label, candidateEntropy) in GetKnownCryptoKeyEntropies())
						{
							var retry = DpapiBlobCrypto.Decrypt(blob, masterKey, candidateEntropy);
							if (retry.Cleartext != null && retry.Cleartext.Length > 0)
							{
								this.LogVerbose(smb, $"Get-TBODpapiBlob retried decrypt with known {label} entropy for {input.Path ?? "inline"} and recovered cleartext.");
								decryptResult = retry;
								break;
							}
						}
					}
				}

				var cleartextBytes = decryptResult.Cleartext;
				var cleartextText = cleartextBytes != null ? DpapiHelpers.TryDecodeCleartext(cleartextBytes) : null;
				TryWriteBlobRecordToCache(smb, cacheDb, cacheMachineId, input, blob, parseFailureReason: null);
				if (cleartextBytes != null && cleartextBytes.Length > 0)
					TryWriteCleartextToCache(smb, cacheDb, cacheMachineId, input, blob, cleartextBytes);

				this.WriteObject(new TboDpapiBlobDecryptionInfo
				{
					ServerName = this.ServerName,
					Source = input.Source,
					Path = input.Path,
					ValueName = input.ValueName,
					Offset = input.Offset,
					CredentialGuid = blob.GuidCredential.ToString(),
					MasterKeyGuid = blob.GuidMasterKey.ToString(),
					Flags = blob.Flags,
					Description = blob.Description,
					CryptAlgorithmId = blob.CryptAlgorithm,
					CryptAlgorithm = DpapiBlobCrypto.ResolveCipherAlgorithmName(blob.CryptAlgorithm, blob.CryptAlgorithmLength),
					HashAlgorithmId = blob.HashAlgorithm,
					HashAlgorithm = DpapiBlobCrypto.ResolveHashAlgorithmName(blob.HashAlgorithm, blob.HashAlgorithmLength),
					Cleartext = cleartextText,
					CleartextHex = cleartextBytes?.ToHexString(),
					CleartextBytes = cleartextBytes,
					HmacValidated = decryptResult.HmacValidated,
					FailureReason = decryptResult.FailureReason
				});
			}
			finally
			{
				cacheDb?.Dispose();
			}
		}

		private DpapiBlobInput ResolveInput(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			if (this.ParameterSetName == InputObjectParameterSet)
			{
				if (this.InputObject == null)
					throw new ArgumentException("InputObject must be provided.", nameof(this.InputObject));

				var offset = this.Offset != 0 ? this.Offset : this.InputObject.MatchOffset;
				if (this.InputObject.Source.Equals("Registry", StringComparison.OrdinalIgnoreCase))
				{
					if (string.IsNullOrWhiteSpace(this.InputObject.ValueName))
						throw new ArgumentException("Registry blob input is missing ValueName.");
					return ReadRegistryInput(smb, this.InputObject.Path, this.InputObject.ValueName, offset, cancellationToken);
				}

				return ReadFileInput(smb, this.InputObject.Path, offset, cancellationToken);
			}

			if (this.ParameterSetName == RegistryParameterSet)
			{
				return ReadRegistryInput(smb, this.RegistryPath, this.ValueName, this.Offset, cancellationToken);
			}

			if (this.ParameterSetName == FileParameterSet)
			{
				return ReadFileInput(smb, this.Path, this.Offset, cancellationToken);
			}

			if (this.ParameterSetName == BytesParameterSet)
			{
				if (this.BlobBytes == null || this.BlobBytes.Length == 0)
					throw new ArgumentException("BlobBytes must be provided.", nameof(this.BlobBytes));
				return new DpapiBlobInput
				{
					Data = this.BlobBytes,
					Offset = this.Offset,
					Source = "Bytes"
				};
			}

			if (this.ParameterSetName == HexParameterSet)
			{
				if (string.IsNullOrWhiteSpace(this.BlobHex))
					throw new ArgumentException("BlobHex must be provided.", nameof(this.BlobHex));
				return new DpapiBlobInput
				{
					Data = BinaryHelper.ParseHexString(this.BlobHex.AsSpan()),
					Offset = this.Offset,
					Source = "Hex"
				};
			}

			if (this.ParameterSetName == Base64ParameterSet)
			{
				if (string.IsNullOrWhiteSpace(this.BlobBase64))
					throw new ArgumentException("BlobBase64 must be provided.", nameof(this.BlobBase64));
				return new DpapiBlobInput
				{
					Data = Convert.FromBase64String(this.BlobBase64),
					Offset = this.Offset,
					Source = "Base64"
				};
			}

			throw new InvalidOperationException("Unsupported parameter set.");
		}

		private DpapiBlobInput ReadFileInput(ISmbProviderInfo smb, string path, int offset, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(this.Path));

			var uncPath = ResolveToUncPath(path, nameof(this.Path));
			if (string.IsNullOrEmpty(uncPath.ShareName))
				throw new ArgumentException($"Path must include a share name: {uncPath}", nameof(this.Path));

			if (!string.IsNullOrEmpty(uncPath.ServerName)
				&& !uncPath.ServerName.Equals(this.ServerName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"ServerName '{this.ServerName}' does not match UNC host '{uncPath.ServerName}'.", nameof(this.ServerName));

			var bytes = DpapiHelpers.ReadFileBytes(smb, uncPath, cancellationToken);
			return new DpapiBlobInput
			{
				Source = "File",
				Path = uncPath.ToString(),
				Offset = offset,
				Data = bytes
			};
		}

		private DpapiBlobInput ReadRegistryInput(ISmbProviderInfo smb, string registryPath, string valueName, int offset, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(registryPath))
				throw new ArgumentException("RegistryPath must be provided.", nameof(this.RegistryPath));
			if (string.IsNullOrWhiteSpace(valueName))
				throw new ArgumentException("ValueName must be provided.", nameof(this.ValueName));

			var parsedPath = ParseRegistryPath(registryPath, nameof(this.RegistryPath));
			var valueInfo = ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var key = OpenRegistryKey(session.Client, parsedPath, RegistryAccessRights.QueryValue, cancellationToken);
				return key.GetValue(valueName, cancellationToken).GetAwaiter().GetResult();
			});

			if (valueInfo.Bytes == null || valueInfo.Bytes.Length == 0)
				throw new InvalidDataException($"Registry value '{registryPath}\\{valueName}' did not contain binary data.");

			return new DpapiBlobInput
			{
				Source = "Registry",
				Path = parsedPath.KeyPath,
				ValueName = valueName,
				Offset = offset,
				Data = valueInfo.Bytes
			};
		}


		private byte[]? ResolveMasterKey()
		{
			if (this.MasterKeyBytes != null && this.MasterKeyBytes.Length > 0)
				return this.MasterKeyBytes;
			if (!string.IsNullOrWhiteSpace(this.MasterKey))
				return BinaryHelper.ParseHexString(this.MasterKey.AsSpan());
			return null;
		}

		private byte[]? ResolveEntropy()
		{
			if (this.EntropyBytes != null && this.EntropyBytes.Length > 0)
				return this.EntropyBytes;
			if (!string.IsNullOrWhiteSpace(this.Entropy))
				return BinaryHelper.ParseHexString(this.Entropy.AsSpan());
			return null;
		}

		private void TryWriteBlobRecordToCache(
			ISmbProviderInfo smb,
			TboCacheDatabase? cacheDb,
			long cacheMachineId,
			DpapiBlobInput input,
			DpapiBlob? blob,
			string? parseFailureReason)
		{
			if (cacheDb == null || cacheMachineId <= 0 || input == null)
				return;
			if (input.Offset < 0)
				return;

			try
			{
				var blobKey = BuildBlobKey(input);
				cacheDb.UpsertDpapiBlob(
					machineId: cacheMachineId,
					blobKey: blobKey,
					source: input.Source,
					path: input.Path ?? "inline",
					valueName: input.ValueName,
					valueType: null,
					dataLength: input.Data.Length,
					fileSize: input.Source.Equals("File", StringComparison.OrdinalIgnoreCase) ? input.Data.Length : null,
					matchOffset: input.Offset,
					bytesScanned: input.Data.Length,
					credentialGuid: blob?.GuidCredential.ToString(),
					masterKeyGuid: blob?.GuidMasterKey.ToString(),
					flags: blob?.Flags,
					description: blob?.Description,
					cryptAlgorithmId: blob?.CryptAlgorithm,
					hashAlgorithmId: blob?.HashAlgorithm,
					parseFailureReason: parseFailureReason);
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBODpapiBlob failed to write cache blob record for {this.ServerName}", ex, emitWarning: false);
				this.LogWarning(smb, $"Get-TBODpapiBlob cache write failed: {ex.Message}");
			}
		}

		private void TryWriteCleartextToCache(
			ISmbProviderInfo smb,
			TboCacheDatabase? cacheDb,
			long cacheMachineId,
			DpapiBlobInput input,
			DpapiBlob blob,
			byte[] cleartextBytes)
		{
			if (cacheDb == null || cacheMachineId <= 0)
				return;
			if (cleartextBytes == null || cleartextBytes.Length == 0)
				return;

			const int MaxCacheBytes = 8192;
			var payload = cleartextBytes.Length <= MaxCacheBytes
				? cleartextBytes
				: cleartextBytes.AsSpan(0, MaxCacheBytes).ToArray();

			try
			{
				var sourcePath = BuildSourcePath(input) ?? "inline";
				var identifier = $"{sourcePath}|{input.Offset.ToString(CultureInfo.InvariantCulture)}|{blob.GuidMasterKey}";
				var credentialId = cacheDb.UpsertCredential("dpapi_cleartext", identifier, payload);
				var contextJson = $"{{\"offset\":{input.Offset.ToString(CultureInfo.InvariantCulture)},\"masterKeyGuid\":\"{blob.GuidMasterKey}\",\"source\":\"{input.Source}\"}}";
				cacheDb.InsertObservation(
					machineId: cacheMachineId,
					principalId: null,
					credentialId: credentialId,
					sourceKind: CacheSourceKind,
					sourcePath: sourcePath,
					contextJson: contextJson,
					confidence: 70);
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBODpapiBlob failed to write cache credential record for {this.ServerName}", ex, emitWarning: false);
			}
		}

		private static string BuildBlobKey(DpapiBlobInput input)
		{
			var source = input.Source?.Trim() ?? string.Empty;
			var path = input.Path?.Trim() ?? "inline";
			var valueName = input.ValueName?.Trim() ?? string.Empty;

			if (source.Equals("Registry", StringComparison.OrdinalIgnoreCase))
				return $"Registry|{path}|{valueName}|{input.Offset}";

			if (source.Equals("File", StringComparison.OrdinalIgnoreCase))
				return $"File|{path}|{input.Offset}";

			var prefixLen = Math.Min(input.Data.Length, 16);
			var prefix = prefixLen > 0 ? Convert.ToHexString(input.Data.AsSpan(0, prefixLen)) : "empty";
			return $"{source}|{path}|{input.Offset}|{prefix}";
		}

		private static string? BuildSourcePath(DpapiBlobInput input)
		{
			if (input == null)
				return null;

			if (input.Source.Equals("Registry", StringComparison.OrdinalIgnoreCase)
				&& !string.IsNullOrWhiteSpace(input.Path)
				&& !string.IsNullOrWhiteSpace(input.ValueName))
			{
				return $"{input.Path}\\{input.ValueName}";
			}

			return input.Path;
		}

		private static bool ShouldTryKnownCngEntropyFallback(
			DpapiBlobInput input,
			byte[]? entropy,
			DpapiBlobDecryptionResult decryptResult)
		{
			if (entropy != null && entropy.Length > 0)
				return false;
			if (decryptResult.Cleartext != null && decryptResult.Cleartext.Length > 0)
				return false;
			if (!input.Source.Equals("File", StringComparison.OrdinalIgnoreCase))
				return false;
			if (string.IsNullOrWhiteSpace(input.Path))
				return false;

			return input.Path.IndexOf(@"\Microsoft\Crypto\Keys\", StringComparison.OrdinalIgnoreCase) >= 0;
		}

		private static IReadOnlyList<(string Label, byte[] Entropy)> GetKnownCryptoKeyEntropies()
		{
			var entropies = new List<(string Label, byte[] Entropy)>
			{
				("CNG", MachineCertificateHelpers.GetCngEntropy()),
				("PrivateKeyProperties", NgcCryptoKeysHelpers.GetPrivateKeyPropertiesEntropy())
			};

			var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			var deduped = new List<(string Label, byte[] Entropy)>(entropies.Count);
			foreach (var entry in entropies)
			{
				if (entry.Entropy == null || entry.Entropy.Length == 0)
					continue;

				var key = Convert.ToHexString(entry.Entropy);
				if (!seen.Add(key))
					continue;

				deduped.Add(entry);
			}

			return deduped;
		}

		private string BuildMissingMasterKeyFailureReason(TboCacheDatabase? cacheDb, long cacheMachineId, Guid masterKeyGuid)
		{
			if (cacheDb == null || cacheMachineId <= 0)
				return $"Master key {masterKeyGuid} was not provided and was not found in cache.";

			try
			{
				var state = cacheDb.GetDpapiMasterKeyPresence(cacheMachineId, masterKeyGuid.ToString());
				if (!state.Exists)
					return $"Master key {masterKeyGuid} was not found in the supplied key set and has not been seen in SQLite cache.";
				if (state.HasCleartext)
					return $"Master key {masterKeyGuid} is present in SQLite cache, but was unavailable in the current key set.";

				return $"Master key {masterKeyGuid} is tracked in SQLite cache, but its cleartext key has not been recovered yet.";
			}
			catch
			{
				return $"Master key {masterKeyGuid} was not provided and was not found in cache.";
			}
		}

		private void TryRecordMissingMasterKeyTarget(
			ISmbProviderInfo smb,
			TboCacheDatabase? cacheDb,
			long cacheMachineId,
			DpapiBlobInput input,
			DpapiBlob blob,
			string? failureReason)
		{
			if (cacheDb == null || cacheMachineId <= 0)
				return;

			try
			{
				var sourcePath = BuildSourcePath(input) ?? "inline";
				cacheDb.UpsertDpapiMasterKeyTarget(
					machineId: cacheMachineId,
					masterKeyGuid: blob.GuidMasterKey.ToString(),
					sourcePath: sourcePath,
					failureReason: failureReason);
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBODpapiBlob failed to record missing master key target for {this.ServerName}", ex, emitWarning: false);
			}
		}


		private UncPath ResolveToUncPath(string path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", paramName);

			if (UncPath.TryParse(path, out var uncPath) && uncPath != null)
				return uncPath;

			ProviderInfo? providerInfo;
			PSDriveInfo? driveInfo;
			string providerPath;
			try
			{
				providerPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out providerInfo, out driveInfo);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"Path could not be resolved: {path}", paramName, ex);
			}

			if (providerInfo == null || !providerInfo.Name.Equals(SmbProvider.ProviderName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Path must be a UNC path or a {SmbProvider.ProviderName} PSDrive path: {path}", paramName);

			if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
				return resolvedUnc;

			throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
		}

		private sealed class DpapiBlobInput
		{
			public string Source { get; init; } = string.Empty;
			public string? Path { get; init; }
			public string? ValueName { get; init; }
			public int Offset { get; init; }
			public byte[] Data { get; init; } = Array.Empty<byte>();
		}
	}
}
