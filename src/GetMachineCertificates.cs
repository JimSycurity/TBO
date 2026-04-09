using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboMachineCertificateInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string SourcePath { get; init; } = string.Empty;
		public string KeyType { get; init; } = string.Empty;
		public string? UniqueName { get; init; }

		public string? MasterKeyGuid { get; init; }
		public uint Flags { get; init; }
		public string? Description { get; init; }
		public uint CryptAlgorithmId { get; init; }
		public string? CryptAlgorithm { get; init; }
		public uint HashAlgorithmId { get; init; }
		public string? HashAlgorithm { get; init; }
		public bool HmacValidated { get; init; }
		public string? FailureReason { get; init; }

		public string? Thumbprint { get; init; }
		public string? Issuer { get; init; }
		public string? Subject { get; init; }
		public DateTime? NotBefore { get; init; }
		public DateTime? NotAfter { get; init; }
		public string[]? EnhancedKeyUsages { get; init; }

		public string? PrivateKeyPem { get; init; }
		public string? CertificatePem { get; init; }
	}

	internal sealed class MachineMyCertificate
	{
		public string Thumbprint { get; init; } = string.Empty;
		public string Issuer { get; init; } = string.Empty;
		public string Subject { get; init; } = string.Empty;
		public DateTime NotBefore { get; init; }
		public DateTime NotAfter { get; init; }
		public string[] EnhancedKeyUsages { get; init; } = Array.Empty<string>();
		public string CertificatePem { get; init; } = string.Empty;
		public string ModulusHex { get; init; } = string.Empty;
	}

	internal static class MachineCertificateHelpers
	{
		internal const string DefaultShareName = "C$";

		private static readonly Regex KeyFileNameRegex = new(
			@"^[0-9A-Fa-f]{32}[_][0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}$",
			RegexOptions.CultureInvariant);

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

		internal static string NormalizeServerName(string? serverName)
			=> DpapiHelpers.NormalizeServerName(serverName);

		internal static string NormalizeShareName(string? shareName)
			=> DpapiHelpers.NormalizeShareName(shareName);

		internal static IEnumerable<UncPath> EnumerateDefaultCapiKeyDirectories(string serverName, string shareName)
		{
			yield return new UncPath(serverName, shareName, @"ProgramData\Microsoft\Crypto\RSA\MachineKeys");
			yield return new UncPath(serverName, shareName, @"Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-18");
			yield return new UncPath(serverName, shareName, @"Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-19");
			yield return new UncPath(serverName, shareName, @"Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-20");
		}

		internal static IEnumerable<UncPath> EnumerateDefaultCngKeyDirectories(string serverName, string shareName)
		{
			yield return new UncPath(serverName, shareName, @"ProgramData\Microsoft\Crypto\Keys");
			yield return new UncPath(serverName, shareName, @"ProgramData\Microsoft\Crypto\SystemKeys");
			yield return new UncPath(serverName, shareName, @"Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys");
		}

		internal static IReadOnlyList<UncPath> EnumerateKeyFiles(
			ISmbProviderInfo smb,
			UncPath directoryPath,
			Action<string>? logWarning,
			Action<string>? logVerbose,
			Action<string, Exception>? logException,
			CancellationToken cancellationToken)
		{
			logWarning ??= _ => { };
			logVerbose ??= _ => { };
			logException ??= (_, _) => { };

			var results = new List<UncPath>();
			var fileSystem = SmbFileSystemResolver.Resolve(smb);
			ISmbDirectory? dir = null;
			try
			{
				dir = fileSystem.OpenDirectory(directoryPath, cancellationToken);
				foreach (var entry in dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
				{
					if (string.IsNullOrWhiteSpace(entry.FileName))
						continue;
					if (entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					if (isDirectory)
						continue;

					var fileName = entry.FileName;
					if (!KeyFileNameRegex.IsMatch(fileName))
						continue;

					results.Add(directoryPath.Append(fileName));
				}
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				logVerbose($"Get-TBOMachineCertificates could not open {directoryPath}: {ex.StatusCode}.");
				return results;
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				logWarning($"Get-TBOMachineCertificates was denied access to {directoryPath}: {ex.StatusCode}.");
				return results;
			}
			catch (Exception ex)
			{
				logException($"Get-TBOMachineCertificates failed to enumerate {directoryPath}", ex);
				throw;
			}
			finally
			{
				dir?.Dispose();
			}

			return results;
		}

		internal static bool TryExtractCapiDpapiBlob(
			ReadOnlySpan<byte> fileBytes,
			out string? uniqueName,
			out byte[]? dpapiBlobBytes,
			out string? failureReason)
		{
			uniqueName = null;
			dpapiBlobBytes = null;
			failureReason = null;

			try
			{
				int offset = 0;
				if (fileBytes.Length < 36)
				{
					failureReason = "Key file is truncated.";
					return false;
				}

				_ = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 8; // version + unk0

				uint descrLen = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;

				uint siPublicKeyLen = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;

				uint siPrivateKeyLen = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;

				uint exPublicKeyLen = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;

				uint exPrivateKeyLen = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;

				uint hashLen = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;

				_ = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4)); // siExportFlagLen
				offset += 4;

				_ = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4)); // exExportFlagLen
				offset += 4;

				if (descrLen > int.MaxValue || fileBytes.Length - offset < (int)descrLen)
				{
					failureReason = "Key file description length is invalid.";
					return false;
				}

				uniqueName = Encoding.UTF8.GetString(fileBytes.Slice(offset, (int)descrLen)).TrimEnd('\0');
				offset += (int)descrLen;

				if (hashLen > int.MaxValue || fileBytes.Length - offset < (int)hashLen)
				{
					failureReason = "Key file hash length is invalid.";
					return false;
				}

				offset += (int)hashLen; // skip CRC/hash blob

				// Parse the embedded RSA metadata blob to locate the following DPAPI blob.
				if (fileBytes.Length - offset < 20)
				{
					failureReason = "Key file is truncated after header.";
					return false;
				}

				offset += 4; // magic
				uint modulusLen = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;
				uint bitLength = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.Slice(offset, 4));
				offset += 4;
				offset += 4; // unk
				offset += 4; // pubexp

				uint modulusBytes = bitLength / 8;
				if (modulusBytes == 0 || modulusLen == 0 || modulusBytes > int.MaxValue)
				{
					failureReason = "Key file RSA header was invalid.";
					return false;
				}

				if (fileBytes.Length - offset < (int)modulusBytes + 8)
				{
					failureReason = "Key file RSA header is truncated.";
					return false;
				}

				offset += checked((int)modulusBytes + 8); // modulus bytes + reserved

				uint dpapiLen = exPublicKeyLen != 0 ? exPrivateKeyLen : siPrivateKeyLen;
				if (dpapiLen == 0)
				{
					failureReason = "Key file did not contain a DPAPI private key blob.";
					return false;
				}

				if (dpapiLen > int.MaxValue || fileBytes.Length - offset < (int)dpapiLen)
				{
					failureReason = "Key file DPAPI blob is truncated.";
					return false;
				}

				dpapiBlobBytes = fileBytes.Slice(offset, (int)dpapiLen).ToArray();
				return true;
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to parse CAPI key file: {ex.Message}";
				return false;
			}
		}

		internal static bool TryExtractCngDpapiBlob(
			ReadOnlySpan<byte> fileBytes,
			out string? uniqueName,
			out byte[]? dpapiBlobBytes,
			out string? failureReason)
		{
			uniqueName = null;
			dpapiBlobBytes = null;
			failureReason = null;

			try
			{
				int offset = 0;
				if (fileBytes.Length < 56)
				{
					failureReason = "Key file is truncated.";
					return false;
				}

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
				offset += 4; // unk1

				if (descrLen > int.MaxValue || fileBytes.Length - offset < (int)descrLen)
				{
					failureReason = "Key file description length is invalid.";
					return false;
				}

				uniqueName = Encoding.Unicode.GetString(fileBytes.Slice(offset, (int)descrLen)).TrimEnd('\0');
				offset += (int)descrLen;

				if (publicPropsLen > int.MaxValue || privatePropsLen > int.MaxValue)
				{
					failureReason = "Key file property lengths are invalid.";
					return false;
				}

				if (fileBytes.Length - offset < (int)publicPropsLen + (int)privatePropsLen)
				{
					failureReason = "Key file properties are truncated.";
					return false;
				}

				offset += checked((int)publicPropsLen + (int)privatePropsLen);

				if (privateKeyLen == 0)
				{
					failureReason = "Key file did not contain a DPAPI private key blob.";
					return false;
				}

				if (privateKeyLen > int.MaxValue || fileBytes.Length - offset < (int)privateKeyLen)
				{
					failureReason = "Key file DPAPI blob is truncated.";
					return false;
				}

				dpapiBlobBytes = fileBytes.Slice(offset, (int)privateKeyLen).ToArray();
				return true;
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to parse CNG key file: {ex.Message}";
				return false;
			}
		}

		internal static bool TryParseDecryptedRsaCapiBlob(
			byte[] decrypted,
			out RSAParameters parameters,
			out string? failureReason)
		{
			parameters = default;
			failureReason = null;

			if (decrypted == null || decrypted.Length < 24)
			{
				failureReason = "Decrypted key blob was empty or truncated.";
				return false;
			}

			try
			{
				int offset = 0;
				_ = Encoding.ASCII.GetString(decrypted, offset, 4); // magic
				offset += 4;

				int modulusLen = BinaryPrimitives.ReadInt32LittleEndian(decrypted.AsSpan(offset, 4));
				offset += 4;

				_ = BinaryPrimitives.ReadInt32LittleEndian(decrypted.AsSpan(offset, 4)); // bitLen
				offset += 4;

				offset += 4; // unk

				var pubExpLe = decrypted.AsSpan(offset, 4).ToArray();
				offset += 4;

				if (modulusLen <= 0 || modulusLen > decrypted.Length - offset)
				{
					failureReason = "Decrypted key blob modulus length is invalid.";
					return false;
				}

				int primeLen = modulusLen / 2;
				if (primeLen <= 0)
				{
					failureReason = "Decrypted key blob prime length is invalid.";
					return false;
				}

				var modulusLe = decrypted.AsSpan(offset, modulusLen).ToArray();
				offset += modulusLen;

				var pLe = decrypted.AsSpan(offset, primeLen).ToArray();
				offset += primeLen;
				var qLe = decrypted.AsSpan(offset, primeLen).ToArray();
				offset += primeLen;
				var dpLe = decrypted.AsSpan(offset, primeLen).ToArray();
				offset += primeLen;
				var dqLe = decrypted.AsSpan(offset, primeLen).ToArray();
				offset += primeLen;
				var inverseQLe = decrypted.AsSpan(offset, primeLen).ToArray();
				offset += primeLen;

				var dLe = decrypted.AsSpan(offset, modulusLen).ToArray();

				var modulus = PadLeft(TrimLeadingZeros(ReverseToBigEndian(modulusLe)), modulusLen);
				var exponent = TrimLeadingZeros(ReverseToBigEndian(pubExpLe));
				var d = PadLeft(TrimLeadingZeros(ReverseToBigEndian(dLe)), modulusLen);
				var p = PadLeft(TrimLeadingZeros(ReverseToBigEndian(pLe)), primeLen);
				var q = PadLeft(TrimLeadingZeros(ReverseToBigEndian(qLe)), primeLen);
				var dp = PadLeft(TrimLeadingZeros(ReverseToBigEndian(dpLe)), primeLen);
				var dq = PadLeft(TrimLeadingZeros(ReverseToBigEndian(dqLe)), primeLen);
				var inverseQ = PadLeft(TrimLeadingZeros(ReverseToBigEndian(inverseQLe)), primeLen);

				parameters = new RSAParameters
				{
					Modulus = modulus,
					Exponent = exponent,
					D = d,
					P = p,
					Q = q,
					DP = dp,
					DQ = dq,
					InverseQ = inverseQ
				};
				return true;
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to parse decrypted RSA blob: {ex.Message}";
				return false;
			}
		}

		private static byte[] ReverseToBigEndian(byte[] littleEndian)
		{
			var copy = littleEndian.ToArray();
			Array.Reverse(copy);
			return copy;
		}

		private static byte[] TrimLeadingZeros(byte[] bigEndian)
		{
			int i = 0;
			while (i < bigEndian.Length - 1 && bigEndian[i] == 0)
				i++;
			return i == 0 ? bigEndian : bigEndian.AsSpan(i).ToArray();
		}

		private static byte[] PadLeft(byte[] bigEndian, int length)
		{
			if (bigEndian.Length >= length)
				return bigEndian;

			var padded = new byte[length];
			Buffer.BlockCopy(bigEndian, 0, padded, length - bigEndian.Length, bigEndian.Length);
			return padded;
		}

		internal static bool TryParseDecryptedRsaCngBlob(
			byte[] decrypted,
			out RSAParameters parameters,
			out string? failureReason)
		{
			parameters = default;
			failureReason = null;

			if (decrypted == null || decrypted.Length < 24)
			{
				failureReason = "Decrypted key blob was empty or truncated.";
				return false;
			}

			try
			{
				int offset = 0;
				offset += 4; // magic

				_ = BinaryPrimitives.ReadInt32LittleEndian(decrypted.AsSpan(offset, 4)); // bitLen
				offset += 4;

				int cbPublicExp = BinaryPrimitives.ReadInt32LittleEndian(decrypted.AsSpan(offset, 4));
				offset += 4;

				int cbModulus = BinaryPrimitives.ReadInt32LittleEndian(decrypted.AsSpan(offset, 4));
				offset += 4;

				int cbPrime1 = BinaryPrimitives.ReadInt32LittleEndian(decrypted.AsSpan(offset, 4));
				offset += 4;

				int cbPrime2 = BinaryPrimitives.ReadInt32LittleEndian(decrypted.AsSpan(offset, 4));
				offset += 4;

				if (cbPublicExp <= 0 || cbModulus <= 0 || cbPrime1 <= 0 || cbPrime2 <= 0)
				{
					failureReason = "Decrypted CNG header lengths were invalid.";
					return false;
				}

				if (decrypted.Length - offset < cbPublicExp + cbModulus + cbPrime1 + cbPrime2)
				{
					failureReason = "Decrypted CNG blob is truncated.";
					return false;
				}

				var pubExp = decrypted.AsSpan(offset, cbPublicExp).ToArray();
				offset += cbPublicExp;
				var modulus = decrypted.AsSpan(offset, cbModulus).ToArray();
				offset += cbModulus;
				var p = decrypted.AsSpan(offset, cbPrime1).ToArray();
				offset += cbPrime1;
				var q = decrypted.AsSpan(offset, cbPrime2).ToArray();
				offset += cbPrime2;

				// Full blobs include the remaining fields. Partial blobs require reconstruction.
				if (decrypted.Length - offset >= cbPrime1 + cbPrime2 + cbPrime1 + cbModulus)
				{
					var dp = decrypted.AsSpan(offset, cbPrime1).ToArray();
					offset += cbPrime1;
					var dq = decrypted.AsSpan(offset, cbPrime2).ToArray();
					offset += cbPrime2;
					var inverseQ = decrypted.AsSpan(offset, cbPrime1).ToArray();
					offset += cbPrime1;
					var d = decrypted.AsSpan(offset, cbModulus).ToArray();

					parameters = new RSAParameters
					{
						Modulus = modulus,
						Exponent = pubExp,
						P = p,
						Q = q,
						DP = dp,
						DQ = dq,
						InverseQ = inverseQ,
						D = d
					};
					return true;
				}

				if (!TryReconstructRsaParametersFromPrimes(modulus, pubExp, p, q, out parameters, out failureReason))
					return false;

				return true;
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to parse decrypted CNG blob: {ex.Message}";
				return false;
			}
		}

		private static bool TryReconstructRsaParametersFromPrimes(
			byte[] modulus,
			byte[] exponent,
			byte[] p,
			byte[] q,
			out RSAParameters parameters,
			out string? failureReason)
		{
			parameters = default;
			failureReason = null;

			try
			{
				var e = ToBigIntegerUnsignedBigEndian(exponent);
				var bp = ToBigIntegerUnsignedBigEndian(p);
				var bq = ToBigIntegerUnsignedBigEndian(q);

				var phi = (bp - BigInteger.One) * (bq - BigInteger.One);
				var d = ModInverse(e, phi);

				var dp = d % (bp - BigInteger.One);
				var dq = d % (bq - BigInteger.One);
				var inverseQ = ModInverse(bq, bp);

				var cbPrime1 = p.Length;
				var cbPrime2 = q.Length;
				var cbModulus = modulus.Length;

				parameters = new RSAParameters
				{
					Modulus = modulus,
					Exponent = exponent,
					P = p,
					Q = q,
					D = PadLeft(ToUnsignedBigEndian(d), cbModulus),
					DP = PadLeft(ToUnsignedBigEndian(dp), cbPrime1),
					DQ = PadLeft(ToUnsignedBigEndian(dq), cbPrime2),
					InverseQ = PadLeft(ToUnsignedBigEndian(inverseQ), cbPrime1)
				};
				return true;
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to reconstruct RSA parameters: {ex.Message}";
				return false;
			}
		}

		private static BigInteger ToBigIntegerUnsignedBigEndian(byte[] bigEndian)
		{
			var tmp = bigEndian.ToArray();
			Array.Reverse(tmp);
			var unsigned = new byte[tmp.Length + 1];
			Buffer.BlockCopy(tmp, 0, unsigned, 0, tmp.Length);
			return new BigInteger(unsigned);
		}

		private static byte[] ToUnsignedBigEndian(BigInteger value)
		{
			var little = value.ToByteArray(isUnsigned: true, isBigEndian: false);
			Array.Reverse(little);
			return TrimLeadingZeros(little);
		}

		private static BigInteger ModInverse(BigInteger a, BigInteger m)
		{
			BigInteger t = BigInteger.Zero;
			BigInteger newT = BigInteger.One;
			BigInteger r = m;
			BigInteger newR = a % m;

			while (newR != 0)
			{
				var quotient = r / newR;
				(t, newT) = (newT, t - quotient * newT);
				(r, newR) = (newR, r - quotient * newR);
			}

			if (r > 1)
				throw new InvalidOperationException("Value is not invertible.");
			if (t < 0)
				t += m;
			return t;
		}

		internal static IReadOnlyDictionary<string, MachineMyCertificate> LoadMachineMyCertificates(
			IRegistryClient client,
			CancellationToken cancellationToken,
			Action<string>? logVerbose,
			Action<string, Exception>? logException)
		{
			logVerbose ??= _ => { };
			logException ??= (_, _) => { };

			var results = new Dictionary<string, MachineMyCertificate>(StringComparer.OrdinalIgnoreCase);

			// Mirrors SharpDPAPI's default store enumeration (X509Store(StoreLocation) -> StoreName.My).
			var certsSpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				@"SOFTWARE\Microsoft\SystemCertificates\MY\Certificates");

			using var certsKey = RegistryHelpers.OpenRegistryKey(client, certsSpec, RegistryAccessRights.EnumerateSubkeys, cancellationToken);
			var certKeys = RegistryHelpers.CollectSubkeys(certsKey, cancellationToken);
			foreach (var certKeyInfo in certKeys)
			{
				if (string.IsNullOrWhiteSpace(certKeyInfo.KeyName))
					continue;

				using var certKey = certsKey.OpenSubkey(certKeyInfo.KeyName, RegistryAccessRights.QueryValue, RegistryHelpers.BackupOptions, cancellationToken).GetAwaiter().GetResult();
				var values = RegistryHelpers.CollectValues(certKey, includeData: true, cancellationToken);
				var blob = values.FirstOrDefault(v => string.Equals(v.Name, "Blob", StringComparison.OrdinalIgnoreCase))?.Bytes;
				if (blob == null || blob.Length == 0)
					continue;

				try
				{
					using var cert = new X509Certificate2(blob);
					using var rsa = cert.GetRSAPublicKey();
					if (rsa == null)
						continue;

					var rsaParams = rsa.ExportParameters(includePrivateParameters: false);
					if (rsaParams.Modulus == null || rsaParams.Modulus.Length == 0)
						continue;

					var ekuList = new List<string>();
					foreach (var ext in cert.Extensions)
					{
						if (ext is X509EnhancedKeyUsageExtension ekuExt)
						{
							foreach (var oid in ekuExt.EnhancedKeyUsages)
							{
								var name = string.IsNullOrWhiteSpace(oid.FriendlyName) ? "Enhanced Key Usage" : oid.FriendlyName;
								ekuList.Add($"{name} ({oid.Value})");
							}
						}
					}

					var modulusHex = Convert.ToHexString(rsaParams.Modulus);
					results[modulusHex] = new MachineMyCertificate
					{
						Thumbprint = cert.Thumbprint ?? string.Empty,
						Issuer = cert.Issuer ?? string.Empty,
						Subject = cert.Subject ?? string.Empty,
						NotBefore = cert.NotBefore,
						NotAfter = cert.NotAfter,
						EnhancedKeyUsages = ekuList.ToArray(),
						CertificatePem = cert.ExportCertificatePem(),
						ModulusHex = modulusHex
					};
				}
				catch (Exception ex)
				{
					logVerbose($"Get-TBOMachineCertificates failed to parse certificate registry blob for '{certKeyInfo.KeyName}': {ex.Message}");
					logException($"Get-TBOMachineCertificates failed to parse certificate registry blob for '{certKeyInfo.KeyName}'", ex);
				}
			}

			return results;
		}

		internal static byte[] GetCngEntropy()
		{
			// Mimics mimikatz/SharpDPAPI CNG entropy: "xT5rZW5qVVbrvpuA\0"
			var bytes = Encoding.UTF8.GetBytes("xT5rZW5qVVbrvpuA");
			var entropy = new byte[bytes.Length + 1];
			Buffer.BlockCopy(bytes, 0, entropy, 0, bytes.Length);
			return entropy;
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOMachineCertificates")]
	[OutputType(typeof(TboMachineCertificateInfo))]
	public sealed class GetTBOMachineCertificates : TboRegCmdlet
	{
		[Parameter]
		public string ShareName { get; set; } = MachineCertificateHelpers.DefaultShareName;

		[Parameter]
		public TboDpapiMasterKeyInfo[]? MasterKeys { get; set; }

		[Parameter]
		public SwitchParameter ShowAll { get; set; }

		[Parameter]
		public SwitchParameter SkipCng { get; set; }

		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var serverName = MachineCertificateHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var shareName = MachineCertificateHelpers.NormalizeShareName(this.ShareName);
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("ShareName must be provided.", nameof(this.ShareName));

			var masterKeySet = DpapiHelpers.BuildMasterKeySet(this.MasterKeys, msg => this.LogWarning(smb, msg), "Get-TBOMachineCertificates");
			if (this.ResolveCacheIngestionEnabled(this.Cache))
			{
				var cached = DpapiHelpers.LoadCachedMasterKeys(this.CachePath, serverName, msg => this.LogVerbose(smb, msg), msg => this.LogWarning(smb, msg));
				DpapiHelpers.MergeMasterKeySets(masterKeySet, cached);
			}
			if (masterKeySet.Count == 0)
			{
				this.LogWarning(smb, "Get-TBOMachineCertificates: no master keys available (supply -MasterKeys or enable -Cache).");
				return;
			}

			var myCerts = new Dictionary<string, MachineMyCertificate>(StringComparer.OrdinalIgnoreCase);
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				myCerts = new Dictionary<string, MachineMyCertificate>(
					MachineCertificateHelpers.LoadMachineMyCertificates(
						session.Client,
						cancellationToken,
						logVerbose: msg => this.LogVerbose(smb, msg),
						logException: (ctx, ex) => this.LogException(smb, ctx, ex)),
					StringComparer.OrdinalIgnoreCase);
			});

			var cngEntropy = MachineCertificateHelpers.GetCngEntropy();

			foreach (var dir in MachineCertificateHelpers.EnumerateDefaultCapiKeyDirectories(serverName, shareName))
			{
				foreach (var file in MachineCertificateHelpers.EnumerateKeyFiles(
					smb,
					dir,
					logWarning: msg => this.LogWarning(smb, msg),
					logVerbose: msg => this.LogVerbose(smb, msg),
					logException: (ctx, ex) => this.LogException(smb, ctx, ex),
					cancellationToken))
				{
					cancellationToken.ThrowIfCancellationRequested();
					var result = ProcessKeyFile(
						smb,
						file,
						keyType: "CAPI",
						masterKeySet,
						myCerts,
						entropy: null,
						cancellationToken);
					if (result == null)
						continue;
					if (!this.ShowAll.IsPresent && string.IsNullOrWhiteSpace(result.Thumbprint))
						continue;
					this.WriteObject(result);
				}
			}

			if (this.SkipCng.IsPresent)
				return;

			foreach (var dir in MachineCertificateHelpers.EnumerateDefaultCngKeyDirectories(serverName, shareName))
			{
				foreach (var file in MachineCertificateHelpers.EnumerateKeyFiles(
					smb,
					dir,
					logWarning: msg => this.LogWarning(smb, msg),
					logVerbose: msg => this.LogVerbose(smb, msg),
					logException: (ctx, ex) => this.LogException(smb, ctx, ex),
					cancellationToken))
				{
					cancellationToken.ThrowIfCancellationRequested();
					var result = ProcessKeyFile(
						smb,
						file,
						keyType: "CNG",
						masterKeySet,
						myCerts,
						entropy: cngEntropy,
						cancellationToken);
					if (result == null)
						continue;
					if (!this.ShowAll.IsPresent && string.IsNullOrWhiteSpace(result.Thumbprint))
						continue;
					this.WriteObject(result);
				}
			}
		}

		private TboMachineCertificateInfo? ProcessKeyFile(
			ISmbProviderInfo smb,
			UncPath path,
			string keyType,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			IReadOnlyDictionary<string, MachineMyCertificate> myCerts,
			byte[]? entropy,
			CancellationToken cancellationToken)
		{
			byte[] bytes;
			try
			{
				bytes = DpapiHelpers.ReadFileBytes(smb, path, cancellationToken);
			}
			catch (NtstatusException ex) when (MachineCertificateHelpers.IsMissingPath(ex))
			{
				this.LogVerbose(smb, $"Get-TBOMachineCertificates could not read {path}: {ex.StatusCode}.");
				return null;
			}
			catch (NtstatusException ex) when (MachineCertificateHelpers.IsAccessDenied(ex))
			{
				this.LogWarning(smb, $"Get-TBOMachineCertificates was denied access to {path}: {ex.StatusCode}.");
				return null;
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBOMachineCertificates failed to read '{path}'", ex);
				return null;
			}

			string? uniqueName;
			byte[]? dpapiBlobBytes;
			string? parseFailure;
			bool extracted = keyType == "CNG"
				? MachineCertificateHelpers.TryExtractCngDpapiBlob(bytes, out uniqueName, out dpapiBlobBytes, out parseFailure)
				: MachineCertificateHelpers.TryExtractCapiDpapiBlob(bytes, out uniqueName, out dpapiBlobBytes, out parseFailure);

			if (!extracted || dpapiBlobBytes == null || dpapiBlobBytes.Length == 0)
			{
				this.LogVerbose(smb, $"Get-TBOMachineCertificates failed to parse {keyType} key file {path}: {parseFailure}");
				return null;
			}

			DpapiBlob blob;
			try
			{
				blob = DpapiBlob.Parse(dpapiBlobBytes);
			}
			catch (Exception ex)
			{
				this.LogVerbose(smb, $"Get-TBOMachineCertificates failed to parse DPAPI blob for {path}: {ex.Message}");
				return new TboMachineCertificateInfo
				{
					ServerName = this.ServerName,
					SourcePath = path.ToString(),
					KeyType = keyType,
					UniqueName = uniqueName,
					FailureReason = $"Failed to parse DPAPI blob: {ex.Message}"
				};
			}

			var masterKeyGuid = blob.GuidMasterKey;
			if (!masterKeySet.TryGetValue(masterKeyGuid, out var masterKeyBytes) || masterKeyBytes.Length == 0)
			{
				return new TboMachineCertificateInfo
				{
					ServerName = this.ServerName,
					SourcePath = path.ToString(),
					KeyType = keyType,
					UniqueName = uniqueName,
					MasterKeyGuid = masterKeyGuid.ToString(),
					Flags = blob.Flags,
					Description = blob.Description,
					CryptAlgorithmId = blob.CryptAlgorithm,
					CryptAlgorithm = DpapiBlobCrypto.ResolveCipherAlgorithmName(blob.CryptAlgorithm, blob.CryptAlgorithmLength),
					HashAlgorithmId = blob.HashAlgorithm,
					HashAlgorithm = DpapiBlobCrypto.ResolveHashAlgorithmName(blob.HashAlgorithm, blob.HashAlgorithmLength),
					HmacValidated = false,
					FailureReason = $"Master key {masterKeyGuid} not supplied."
				};
			}

			var decryptResult = DpapiBlobCrypto.Decrypt(blob, masterKeyBytes, entropy);
			if (!decryptResult.Success || decryptResult.Cleartext == null || decryptResult.Cleartext.Length == 0)
			{
				return new TboMachineCertificateInfo
				{
					ServerName = this.ServerName,
					SourcePath = path.ToString(),
					KeyType = keyType,
					UniqueName = uniqueName,
					MasterKeyGuid = masterKeyGuid.ToString(),
					Flags = blob.Flags,
					Description = blob.Description,
					CryptAlgorithmId = blob.CryptAlgorithm,
					CryptAlgorithm = DpapiBlobCrypto.ResolveCipherAlgorithmName(blob.CryptAlgorithm, blob.CryptAlgorithmLength),
					HashAlgorithmId = blob.HashAlgorithm,
					HashAlgorithm = DpapiBlobCrypto.ResolveHashAlgorithmName(blob.HashAlgorithm, blob.HashAlgorithmLength),
					HmacValidated = decryptResult.HmacValidated,
					FailureReason = decryptResult.FailureReason ?? "DPAPI decrypt failed."
				};
			}

			var decryptedKeyBlob = decryptResult.Cleartext;
			RSAParameters rsaParams;
			string? rsaFailure;
			bool rsaOk = keyType == "CNG"
				? MachineCertificateHelpers.TryParseDecryptedRsaCngBlob(decryptedKeyBlob, out rsaParams, out rsaFailure)
				: MachineCertificateHelpers.TryParseDecryptedRsaCapiBlob(decryptedKeyBlob, out rsaParams, out rsaFailure);

			if (!rsaOk)
			{
				return new TboMachineCertificateInfo
				{
					ServerName = this.ServerName,
					SourcePath = path.ToString(),
					KeyType = keyType,
					UniqueName = uniqueName,
					MasterKeyGuid = masterKeyGuid.ToString(),
					Flags = blob.Flags,
					Description = blob.Description,
					CryptAlgorithmId = blob.CryptAlgorithm,
					CryptAlgorithm = DpapiBlobCrypto.ResolveCipherAlgorithmName(blob.CryptAlgorithm, blob.CryptAlgorithmLength),
					HashAlgorithmId = blob.HashAlgorithm,
					HashAlgorithm = DpapiBlobCrypto.ResolveHashAlgorithmName(blob.HashAlgorithm, blob.HashAlgorithmLength),
					HmacValidated = decryptResult.HmacValidated,
					FailureReason = rsaFailure ?? "Failed to parse decrypted RSA key blob."
				};
			}

			string? privateKeyPem = null;
			string? modulusHex = null;
			try
			{
				using var rsa = RSA.Create();
				rsa.ImportParameters(rsaParams);
				privateKeyPem = rsa.ExportRSAPrivateKeyPem();
				modulusHex = rsaParams.Modulus != null ? Convert.ToHexString(rsaParams.Modulus) : null;
			}
			catch (Exception ex)
			{
				return new TboMachineCertificateInfo
				{
					ServerName = this.ServerName,
					SourcePath = path.ToString(),
					KeyType = keyType,
					UniqueName = uniqueName,
					MasterKeyGuid = masterKeyGuid.ToString(),
					Flags = blob.Flags,
					Description = blob.Description,
					CryptAlgorithmId = blob.CryptAlgorithm,
					CryptAlgorithm = DpapiBlobCrypto.ResolveCipherAlgorithmName(blob.CryptAlgorithm, blob.CryptAlgorithmLength),
					HashAlgorithmId = blob.HashAlgorithm,
					HashAlgorithm = DpapiBlobCrypto.ResolveHashAlgorithmName(blob.HashAlgorithm, blob.HashAlgorithmLength),
					HmacValidated = decryptResult.HmacValidated,
					FailureReason = $"Failed to build RSA key: {ex.Message}"
				};
			}

			MachineMyCertificate? cert = null;
			if (!string.IsNullOrWhiteSpace(modulusHex))
			{
				myCerts.TryGetValue(modulusHex, out cert);
			}

			return new TboMachineCertificateInfo
			{
				ServerName = this.ServerName,
				SourcePath = path.ToString(),
				KeyType = keyType,
				UniqueName = uniqueName,
				MasterKeyGuid = masterKeyGuid.ToString(),
				Flags = blob.Flags,
				Description = blob.Description,
				CryptAlgorithmId = blob.CryptAlgorithm,
				CryptAlgorithm = DpapiBlobCrypto.ResolveCipherAlgorithmName(blob.CryptAlgorithm, blob.CryptAlgorithmLength),
				HashAlgorithmId = blob.HashAlgorithm,
				HashAlgorithm = DpapiBlobCrypto.ResolveHashAlgorithmName(blob.HashAlgorithm, blob.HashAlgorithmLength),
				HmacValidated = decryptResult.HmacValidated,
				FailureReason = null,
				Thumbprint = cert?.Thumbprint,
				Issuer = cert?.Issuer,
				Subject = cert?.Subject,
				NotBefore = cert?.NotBefore,
				NotAfter = cert?.NotAfter,
				EnhancedKeyUsages = cert?.EnhancedKeyUsages,
				PrivateKeyPem = privateKeyPem,
				CertificatePem = cert?.CertificatePem
			};
		}
	}
}
