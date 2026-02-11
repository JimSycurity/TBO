using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class DpapiBlob
	{
		public uint Version { get; init; }
		public Guid GuidCredential { get; init; }
		public uint MasterKeyVersion { get; init; }
		public Guid GuidMasterKey { get; init; }
		public uint Flags { get; init; }
		public string Description { get; init; } = string.Empty;
		public uint CryptAlgorithm { get; init; }
		public uint CryptAlgorithmLength { get; init; }
		public byte[] Salt { get; init; } = Array.Empty<byte>();
		public uint HmacKeyLength { get; init; }
		public byte[] HmacKey { get; init; } = Array.Empty<byte>();
		public uint HashAlgorithm { get; init; }
		public uint HashAlgorithmLength { get; init; }
		public byte[] Hmac { get; init; } = Array.Empty<byte>();
		public byte[] Data { get; init; } = Array.Empty<byte>();
		public byte[] Sign { get; init; } = Array.Empty<byte>();
		public byte[] RawData { get; init; } = Array.Empty<byte>();

		public static DpapiBlob Parse(ReadOnlySpan<byte> data, int offset = 0)
		{
			if (data.IsEmpty)
				throw new ArgumentException("DPAPI blob data must be provided.", nameof(data));
			if (offset < 0 || offset >= data.Length)
				throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be within the data bounds.");

			var reader = new BlobReader(data.Slice(offset));
			var version = reader.ReadUInt32();
			var guidCredential = reader.ReadGuid();
			var masterKeyVersion = reader.ReadUInt32();
			var guidMasterKey = reader.ReadGuid();
			var flags = reader.ReadUInt32();

			var descriptionLen = reader.ReadUInt32();
			var descriptionBytes = reader.ReadBytes(checked((int)descriptionLen));
			var description = Encoding.Unicode.GetString(descriptionBytes).TrimEnd('\0');

			var cryptAlgo = reader.ReadUInt32();
			var cryptAlgoLen = reader.ReadUInt32();

			var saltLen = reader.ReadUInt32();
			var salt = reader.ReadBytes(checked((int)saltLen));

			var hmacKeyLen = reader.ReadUInt32();
			var hmacKey = reader.ReadBytes(checked((int)hmacKeyLen));

			var hashAlgo = reader.ReadUInt32();
			var hashAlgoLen = reader.ReadUInt32();

			var hmacLen = reader.ReadUInt32();
			var hmac = reader.ReadBytes(checked((int)hmacLen));

			var dataLen = reader.ReadUInt32();
			var blobData = reader.ReadBytes(checked((int)dataLen));

			var signLen = reader.ReadUInt32();
			var sign = reader.ReadBytes(checked((int)signLen));

			var consumed = reader.Offset;
			var rawData = data.Slice(offset, consumed).ToArray();

			return new DpapiBlob
			{
				Version = version,
				GuidCredential = guidCredential,
				MasterKeyVersion = masterKeyVersion,
				GuidMasterKey = guidMasterKey,
				Flags = flags,
				Description = description,
				CryptAlgorithm = cryptAlgo,
				CryptAlgorithmLength = cryptAlgoLen,
				Salt = salt,
				HmacKeyLength = hmacKeyLen,
				HmacKey = hmacKey,
				HashAlgorithm = hashAlgo,
				HashAlgorithmLength = hashAlgoLen,
				Hmac = hmac,
				Data = blobData,
				Sign = sign,
				RawData = rawData
			};
		}

		private ref struct BlobReader
		{
			private ReadOnlySpan<byte> _buffer;
			private int _offset;

			public BlobReader(ReadOnlySpan<byte> buffer)
			{
				_buffer = buffer;
				_offset = 0;
			}

			public int Offset => _offset;

			public uint ReadUInt32()
			{
				if (_buffer.Length - _offset < 4)
					throw new InvalidDataException("DPAPI blob is truncated.");
				uint value = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.Slice(_offset, 4));
				_offset += 4;
				return value;
			}

			public Guid ReadGuid()
			{
				var bytes = ReadBytes(16);
				return new Guid(bytes);
			}

			public byte[] ReadBytes(int length)
			{
				if (length < 0)
					throw new InvalidDataException("DPAPI blob length is invalid.");
				if (_buffer.Length - _offset < length)
					throw new InvalidDataException("DPAPI blob is truncated.");
				var bytes = _buffer.Slice(_offset, length).ToArray();
				_offset += length;
				return bytes;
			}
		}
	}

	internal sealed class DpapiBlobDecryptionResult
	{
		public bool Success { get; init; }
		public string? FailureReason { get; init; }
		public byte[]? Cleartext { get; init; }
		public bool HmacValidated { get; init; }
	}

	internal static class DpapiBlobCrypto
	{
		internal sealed class DpapiBlobHeader
		{
			internal uint Version { get; init; }
			internal Guid GuidCredential { get; init; }
			internal uint MasterKeyVersion { get; init; }
			internal Guid GuidMasterKey { get; init; }
			internal uint Flags { get; init; }

			internal string? Description { get; init; }
			internal uint? CryptAlgorithm { get; init; }
			internal uint? CryptAlgorithmLength { get; init; }
			internal uint? HashAlgorithm { get; init; }
			internal uint? HashAlgorithmLength { get; init; }
		}

		// Best-effort header parsing for triage/caching scenarios where we only need GUIDs + basic metadata.
		// Returns true if the fixed portion of the header (version, GUIDs, flags) was parsed.
		internal static bool TryParseHeader(ReadOnlySpan<byte> data, int offset, out DpapiBlobHeader header, out string? failureReason)
		{
			header = new DpapiBlobHeader();
			failureReason = null;

			if (data.IsEmpty)
			{
				failureReason = "DPAPI blob data was empty.";
				return false;
			}

			if (offset < 0 || offset >= data.Length)
			{
				failureReason = "Offset must be within the data bounds.";
				return false;
			}

			int pos = offset;

			static bool TryReadUInt32(ReadOnlySpan<byte> buffer, ref int at, out uint value)
			{
				value = 0;
				if (buffer.Length - at < 4)
					return false;
				value = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(at, 4));
				at += 4;
				return true;
			}

			static bool TryReadGuid(ReadOnlySpan<byte> buffer, ref int at, out Guid value)
			{
				value = default;
				if (buffer.Length - at < 16)
					return false;
				value = new Guid(buffer.Slice(at, 16));
				at += 16;
				return true;
			}

			static bool TrySkip(ReadOnlySpan<byte> buffer, ref int at, uint length)
			{
				if (length > int.MaxValue)
					return false;
				var len = unchecked((int)length);
				if (buffer.Length - at < len)
					return false;
				at += len;
				return true;
			}

			if (!TryReadUInt32(data, ref pos, out var version)
				|| !TryReadGuid(data, ref pos, out var guidCredential)
				|| !TryReadUInt32(data, ref pos, out var masterKeyVersion)
				|| !TryReadGuid(data, ref pos, out var guidMasterKey)
				|| !TryReadUInt32(data, ref pos, out var flags))
			{
				failureReason = "DPAPI blob header is truncated.";
				return false;
			}

			string? description = null;
			uint? cryptAlgo = null;
			uint? cryptAlgoLen = null;
			uint? hashAlgo = null;
			uint? hashAlgoLen = null;

			DpapiBlobHeader BuildHeader()
			{
				return new DpapiBlobHeader
				{
					Version = version,
					GuidCredential = guidCredential,
					MasterKeyVersion = masterKeyVersion,
					GuidMasterKey = guidMasterKey,
					Flags = flags,
					Description = description,
					CryptAlgorithm = cryptAlgo,
					CryptAlgorithmLength = cryptAlgoLen,
					HashAlgorithm = hashAlgo,
					HashAlgorithmLength = hashAlgoLen
				};
			}

			if (!TryReadUInt32(data, ref pos, out var descriptionLen))
			{
				header = BuildHeader();
				failureReason = "DPAPI blob is truncated (description length missing).";
				return true;
			}

			if (descriptionLen > 0)
			{
				if (!TrySkip(data, ref pos, descriptionLen))
				{
					header = BuildHeader();
					failureReason = "DPAPI blob is truncated (description bytes missing).";
					return true;
				}

				try
				{
					// Decode from the original slice. We already advanced pos, so re-slice to the correct window.
					var descStart = pos - unchecked((int)descriptionLen);
					description = Encoding.Unicode.GetString(data.Slice(descStart, unchecked((int)descriptionLen))).TrimEnd('\0');
				}
				catch
				{
					description = null;
				}
			}

			if (!TryReadUInt32(data, ref pos, out var cryptAlgoValue) || !TryReadUInt32(data, ref pos, out var cryptAlgoLenValue))
			{
				header = BuildHeader();
				failureReason = "DPAPI blob is truncated (cipher algorithm missing).";
				return true;
			}

			cryptAlgo = cryptAlgoValue;
			cryptAlgoLen = cryptAlgoLenValue;

			if (!TryReadUInt32(data, ref pos, out var saltLen) || !TrySkip(data, ref pos, saltLen))
			{
				header = BuildHeader();
				failureReason = "DPAPI blob is truncated (salt missing).";
				return true;
			}

			if (!TryReadUInt32(data, ref pos, out var hmacKeyLen) || !TrySkip(data, ref pos, hmacKeyLen))
			{
				header = BuildHeader();
				failureReason = "DPAPI blob is truncated (HMAC key missing).";
				return true;
			}

			if (!TryReadUInt32(data, ref pos, out var hashAlgoValue) || !TryReadUInt32(data, ref pos, out var hashAlgoLenValue))
			{
				header = BuildHeader();
				failureReason = "DPAPI blob is truncated (hash algorithm missing).";
				return true;
			}

			hashAlgo = hashAlgoValue;
			hashAlgoLen = hashAlgoLenValue;

			header = BuildHeader();
			return true;
		}

		private sealed class HashAlgorithmInfo
		{
			public HashAlgorithmInfo(uint id, string name, HashAlgorithmName hashName, int digestLength, int blockLength)
			{
				Id = id;
				Name = name;
				HashName = hashName;
				DigestLength = digestLength;
				BlockLength = blockLength;
			}

			public uint Id { get; }
			public string Name { get; }
			public HashAlgorithmName HashName { get; }
			public int DigestLength { get; }
			public int BlockLength { get; }
		}

		private sealed class CipherAlgorithmInfo
		{
			public CipherAlgorithmInfo(uint id, string name, int keyLength, int ivLength, bool fixParity)
			{
				Id = id;
				Name = name;
				KeyLength = keyLength;
				IvLength = ivLength;
				FixParity = fixParity;
			}

			public uint Id { get; }
			public string Name { get; }
			public int KeyLength { get; }
			public int IvLength { get; }
			public bool FixParity { get; }
		}

		private static readonly Dictionary<uint, HashAlgorithmInfo> HashAlgorithms = new()
		{
			{ 0x8003, new HashAlgorithmInfo(0x8003, "MD5", HashAlgorithmName.MD5, 16, 64) },
			{ 0x8004, new HashAlgorithmInfo(0x8004, "SHA1", HashAlgorithmName.SHA1, 20, 64) },
			{ 0x8009, new HashAlgorithmInfo(0x8009, "HMAC", HashAlgorithmName.SHA1, 20, 64) },
			{ 0x800c, new HashAlgorithmInfo(0x800c, "SHA256", HashAlgorithmName.SHA256, 32, 64) },
			{ 0x800d, new HashAlgorithmInfo(0x800d, "SHA384", HashAlgorithmName.SHA384, 48, 128) },
			{ 0x800e, new HashAlgorithmInfo(0x800e, "SHA512", HashAlgorithmName.SHA512, 64, 128) }
		};

		private static readonly Dictionary<uint, CipherAlgorithmInfo> CipherAlgorithms = new()
		{
			{ 0x6601, new CipherAlgorithmInfo(0x6601, "DES", 8, 8, fixParity: true) },
			{ 0x6603, new CipherAlgorithmInfo(0x6603, "DES3", 24, 8, fixParity: true) },
			{ 0x660e, new CipherAlgorithmInfo(0x660e, "AES-128", 16, 16, fixParity: false) },
			{ 0x660f, new CipherAlgorithmInfo(0x660f, "AES-192", 24, 16, fixParity: false) },
			{ 0x6610, new CipherAlgorithmInfo(0x6610, "AES-256", 32, 16, fixParity: false) },
			{ 0x6611, new CipherAlgorithmInfo(0x6611, "AES", 32, 16, fixParity: false) }
		};

		public static DpapiBlobDecryptionResult Decrypt(DpapiBlob blob, byte[] masterKey, byte[]? entropy)
		{
			if (blob == null)
				throw new ArgumentNullException(nameof(blob));
			if (masterKey == null || masterKey.Length == 0)
				return new DpapiBlobDecryptionResult { Success = false, FailureReason = "Master key material was empty." };

			if (!TryResolveCipherAlgorithm(blob.CryptAlgorithm, blob.CryptAlgorithmLength, out var cipherAlgo))
				return new DpapiBlobDecryptionResult { Success = false, FailureReason = $"Unsupported cipher algorithm 0x{blob.CryptAlgorithm:x}." };
			if (!TryResolveHashAlgorithm(blob.HashAlgorithm, blob.HashAlgorithmLength, out var hashAlgo))
				return new DpapiBlobDecryptionResult { Success = false, FailureReason = $"Unsupported hash algorithm 0x{blob.HashAlgorithm:x}." };

			var keyHash = SHA1.HashData(masterKey);
			var sessionKey = ComputeHmac(hashAlgo, keyHash, blob.Salt, entropy);
			var derivedKey = DeriveKey(sessionKey, cipherAlgo, hashAlgo);

			byte[] cleartext;
			try
			{
				var key = derivedKey.AsSpan(0, cipherAlgo.KeyLength).ToArray();
				if (cipherAlgo.FixParity)
					FixDesParity(key);
				var iv = new byte[cipherAlgo.IvLength];
				cleartext = DecryptCbc(cipherAlgo, key, iv, blob.Data);
			}
			catch (Exception ex)
			{
				return new DpapiBlobDecryptionResult
				{
					Success = false,
					FailureReason = $"Decrypt failed: {ex.Message}"
				};
			}

			if (blob.Sign.Length == 0)
			{
				return new DpapiBlobDecryptionResult
				{
					Success = true,
					Cleartext = cleartext,
					HmacValidated = false
				};
			}

			var toSignLength = blob.RawData.Length - 20 - blob.Sign.Length - 4;
			if (toSignLength < 0)
			{
				return new DpapiBlobDecryptionResult
				{
					Success = false,
					FailureReason = "DPAPI blob signature boundaries are invalid."
				};
			}

			var toSign = blob.RawData.AsSpan(20, toSignLength).ToArray();

			var keyBlock = new byte[hashAlgo.BlockLength];
			Buffer.BlockCopy(keyHash, 0, keyBlock, 0, Math.Min(keyHash.Length, keyBlock.Length));

			var ipad = new byte[hashAlgo.BlockLength];
			var opad = new byte[hashAlgo.BlockLength];
			for (int i = 0; i < hashAlgo.BlockLength; i++)
			{
				ipad[i] = (byte)(keyBlock[i] ^ 0x36);
				opad[i] = (byte)(keyBlock[i] ^ 0x5c);
			}

			var inner = ComputeHash(hashAlgo, ipad, blob.Hmac);
			var hmacCalculated1 = ComputeHash(hashAlgo, opad, inner, entropy, toSign);

			var hmacCalculated3 = ComputeHmac(hashAlgo, keyHash, blob.Hmac, entropy, toSign);

			var hmacValid = hmacCalculated1.SequenceEqual(blob.Sign) || hmacCalculated3.SequenceEqual(blob.Sign);

			return new DpapiBlobDecryptionResult
			{
				Success = hmacValid,
				FailureReason = hmacValid ? null : "HMAC validation failed.",
				Cleartext = hmacValid ? cleartext : null,
				HmacValidated = hmacValid
			};
		}

		private static bool TryResolveHashAlgorithm(uint hashAlgo, uint hashAlgoLen, out HashAlgorithmInfo info)
		{
			if (hashAlgo == 0x8009)
			{
				if (hashAlgoLen >= 512 && HashAlgorithms.TryGetValue(0x800e, out info))
					return true;
				if (hashAlgoLen >= 384 && HashAlgorithms.TryGetValue(0x800d, out info))
					return true;
				if (hashAlgoLen >= 256 && HashAlgorithms.TryGetValue(0x800c, out info))
					return true;
				info = HashAlgorithms[0x8004];
				return true;
			}

			return HashAlgorithms.TryGetValue(hashAlgo, out info);
		}

		internal static string ResolveHashAlgorithmName(uint hashAlgo, uint hashAlgoLen)
		{
			return TryResolveHashAlgorithm(hashAlgo, hashAlgoLen, out var info)
				? info.Name
				: $"0x{hashAlgo:x}";
		}

		private static bool TryResolveCipherAlgorithm(uint cryptAlgo, uint cryptAlgoLen, out CipherAlgorithmInfo info)
		{
			if (!CipherAlgorithms.TryGetValue(cryptAlgo, out info))
				return false;

			if (cryptAlgo == 0x6611 && cryptAlgoLen > 0)
			{
				if (cryptAlgoLen == 128 && CipherAlgorithms.TryGetValue(0x660e, out var aes128))
					info = aes128;
				else if (cryptAlgoLen == 192 && CipherAlgorithms.TryGetValue(0x660f, out var aes192))
					info = aes192;
				else if (cryptAlgoLen == 256 && CipherAlgorithms.TryGetValue(0x6610, out var aes256))
					info = aes256;
			}

			return true;
		}

		internal static string ResolveCipherAlgorithmName(uint cryptAlgo, uint cryptAlgoLen)
		{
			return TryResolveCipherAlgorithm(cryptAlgo, cryptAlgoLen, out var info)
				? info.Name
				: $"0x{cryptAlgo:x}";
		}

		private static byte[] DeriveKey(byte[] sessionKey, CipherAlgorithmInfo cipherAlgo, HashAlgorithmInfo hashAlgo)
		{
			byte[] derivedKey;
			if (sessionKey.Length > hashAlgo.BlockLength)
				derivedKey = ComputeHmac(hashAlgo, sessionKey);
			else
				derivedKey = sessionKey;

			if (derivedKey.Length < cipherAlgo.KeyLength)
			{
				var padded = new byte[derivedKey.Length + hashAlgo.BlockLength];
				Buffer.BlockCopy(derivedKey, 0, padded, 0, derivedKey.Length);
				var ipad = new byte[hashAlgo.BlockLength];
				var opad = new byte[hashAlgo.BlockLength];
				for (int i = 0; i < hashAlgo.BlockLength; i++)
				{
					ipad[i] = (byte)(padded[i] ^ 0x36);
					opad[i] = (byte)(padded[i] ^ 0x5c);
				}
				derivedKey = ComputeHash(hashAlgo, ipad)
					.Concat(ComputeHash(hashAlgo, opad))
					.ToArray();
			}

			return derivedKey;
		}

		private static byte[] ComputeHmac(HashAlgorithmInfo hashAlgo, byte[] key, params byte[]?[] parts)
		{
			using var hmac = CreateHmac(hashAlgo.HashName, key);
			foreach (var part in parts)
			{
				if (part == null || part.Length == 0)
					continue;
				hmac.TransformBlock(part, 0, part.Length, null, 0);
			}
			hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
			return hmac.Hash ?? Array.Empty<byte>();
		}

		private static byte[] ComputeHash(HashAlgorithmInfo hashAlgo, params byte[]?[] parts)
		{
			using var hash = IncrementalHash.CreateHash(hashAlgo.HashName);
			foreach (var part in parts)
			{
				if (part == null || part.Length == 0)
					continue;
				hash.AppendData(part);
			}
			return hash.GetHashAndReset();
		}

		private static HMAC CreateHmac(HashAlgorithmName hashName, byte[] key)
		{
			if (hashName == HashAlgorithmName.MD5)
				return new HMACMD5(key);
			if (hashName == HashAlgorithmName.SHA256)
				return new HMACSHA256(key);
			if (hashName == HashAlgorithmName.SHA384)
				return new HMACSHA384(key);
			if (hashName == HashAlgorithmName.SHA512)
				return new HMACSHA512(key);
			return new HMACSHA1(key);
		}

		private static byte[] DecryptCbc(CipherAlgorithmInfo cipherAlgo, byte[] key, byte[] iv, byte[] cipherText)
		{
			SymmetricAlgorithm algo = cipherAlgo.Name switch
			{
				"DES3" => TripleDES.Create(),
				"DES" => DES.Create(),
				_ => Aes.Create()
			};

			algo.Mode = CipherMode.CBC;
			algo.Padding = PaddingMode.PKCS7;
			if (algo is Aes aes)
				aes.KeySize = key.Length * 8;
			algo.Key = key;
			algo.IV = iv;

			using var decryptor = algo.CreateDecryptor();
			return decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
		}

		private static void FixDesParity(byte[] key)
		{
			for (int i = 0; i < key.Length; i++)
			{
				var b = key[i];
				int bitCount = 0;
				for (int bit = 0; bit < 8; bit++)
					bitCount += (b >> bit) & 1;

				if ((bitCount % 2) == 0)
					key[i] ^= 0x01;
			}
		}
	}
}
