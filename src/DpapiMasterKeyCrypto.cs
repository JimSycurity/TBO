using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Titanis.Tbo.Smb2.PowerShell
{
	// Master key layout and crypto flow mirrors DPAPIck/DPAPImk2john structures to stay compatible with Windows DPAPI.
	internal sealed class DpapiMasterKeyFile
	{
		public uint Version { get; init; }
		public string? GuidText { get; init; }
		public Guid? Guid { get; init; }
		public uint Policy { get; init; }
		public DpapiMasterKeyBlock? MasterKey { get; init; }
		public DpapiMasterKeyBlock? BackupKey { get; init; }
		public DpapiMasterKeyCredHistBlock? CredHist { get; init; }
		public DpapiDomainKeyBlock? DomainKey { get; init; }
		public ulong MasterKeyLength { get; init; }
		public ulong BackupKeyLength { get; init; }
		public ulong CredHistLength { get; init; }
		public ulong DomainKeyLength { get; init; }

		public DpapiMasterKeyFileDecryptionResult DecryptWithKey(byte[] keyMaterial)
		{
			if (keyMaterial == null || keyMaterial.Length == 0)
				return new DpapiMasterKeyFileDecryptionResult { FailureReason = "Key material was empty." };

			DpapiMasterKeyDecryptionResult? masterKeyResult = null;
			DpapiMasterKeyDecryptionResult? backupKeyResult = null;

			if (this.MasterKey != null)
				masterKeyResult = this.MasterKey.DecryptWithKey(keyMaterial);
			if (this.BackupKey != null)
				backupKeyResult = this.BackupKey.DecryptWithKey(keyMaterial);

			var success = masterKeyResult?.Success == true || backupKeyResult?.Success == true;
			return new DpapiMasterKeyFileDecryptionResult
			{
				Success = success,
				MasterKeyResult = masterKeyResult,
				BackupKeyResult = backupKeyResult,
				FailureReason = success ? null : "Neither master nor backup key could be decrypted."
			};
		}

		public static DpapiMasterKeyFile Parse(byte[] raw)
		{
			if (raw == null || raw.Length == 0)
				throw new ArgumentException("Master key file data must be provided.", nameof(raw));

			using var stream = new MemoryStream(raw, writable: false);
			using var reader = new BinaryReader(stream, Encoding.Unicode, leaveOpen: true);

			var version = reader.ReadUInt32();
			reader.ReadUInt32();
			reader.ReadUInt32();

			var guidBytes = reader.ReadBytes(72);
			var guidText = Encoding.Unicode.GetString(guidBytes).TrimEnd('\0');
			var guidParsed = TryParseGuid(guidText);

			reader.ReadUInt32();
			reader.ReadUInt32();

			var policy = reader.ReadUInt32();
			var masterKeyLen = reader.ReadUInt64();
			var backupKeyLen = reader.ReadUInt64();
			var credHistLen = reader.ReadUInt64();
			var domainKeyLen = reader.ReadUInt64();

			var remaining = stream.Length - stream.Position;
			if ((long)(masterKeyLen + backupKeyLen + credHistLen + domainKeyLen) > remaining)
				throw new InvalidDataException("Master key file lengths exceed available data.");

			DpapiMasterKeyBlock? masterKey = null;
			DpapiMasterKeyBlock? backupKey = null;
			DpapiMasterKeyCredHistBlock? credHist = null;
			DpapiDomainKeyBlock? domainKey = null;

			if (masterKeyLen > 0)
				masterKey = DpapiMasterKeyBlock.Parse(reader.ReadBytes(checked((int)masterKeyLen)));
			if (backupKeyLen > 0)
				backupKey = DpapiMasterKeyBlock.Parse(reader.ReadBytes(checked((int)backupKeyLen)));
			if (credHistLen > 0)
				credHist = DpapiMasterKeyCredHistBlock.Parse(reader.ReadBytes(checked((int)credHistLen)));
			if (domainKeyLen > 0)
			{
				var domainKeyRaw = reader.ReadBytes(checked((int)domainKeyLen));
				try { domainKey = DpapiDomainKeyBlock.Parse(domainKeyRaw); }
				catch { /* best-effort; non-parseable domain key does not break other decryption paths */ }
			}

			return new DpapiMasterKeyFile
			{
				Version = version,
				GuidText = guidText,
				Guid = guidParsed,
				Policy = policy,
				MasterKeyLength = masterKeyLen,
				BackupKeyLength = backupKeyLen,
				CredHistLength = credHistLen,
				DomainKeyLength = domainKeyLen,
				MasterKey = masterKey,
				BackupKey = backupKey,
				CredHist = credHist,
				DomainKey = domainKey
			};
		}

		private static Guid? TryParseGuid(string? text)
		{
			if (string.IsNullOrWhiteSpace(text))
				return null;

			var trimmed = text.Trim().Trim('{', '}');
			return System.Guid.TryParse(trimmed, out var guid) ? guid : null;
		}
	}

	internal sealed class DpapiMasterKeyFileDecryptionResult
	{
		public bool Success { get; init; }
		public string? FailureReason { get; init; }
		public DpapiMasterKeyDecryptionResult? MasterKeyResult { get; init; }
		public DpapiMasterKeyDecryptionResult? BackupKeyResult { get; init; }
	}

	internal sealed class DpapiMasterKeyBlock
	{
		public uint Version { get; init; }
		public byte[] Iv { get; init; } = Array.Empty<byte>();
		public uint Rounds { get; init; }
		public uint HashAlgorithm { get; init; }
		public uint CipherAlgorithm { get; init; }
		public uint CipherTextLength { get; init; }
		public byte[] CipherText { get; init; } = Array.Empty<byte>();

		public static DpapiMasterKeyBlock Parse(byte[] raw)
		{
			if (raw == null || raw.Length < 32)
				throw new InvalidDataException("Master key block is too short.");

			using var stream = new MemoryStream(raw, writable: false);
			using var reader = new BinaryReader(stream, Encoding.Unicode, leaveOpen: true);

			var version = reader.ReadUInt32();
			var iv = reader.ReadBytes(16);
			var rounds = reader.ReadUInt32();
			var hashAlgo = reader.ReadUInt32();
			var cipherAlgo = reader.ReadUInt32();
			var remaining = stream.Length - stream.Position;
			var cipherText = reader.ReadBytes(checked((int)remaining));

			return new DpapiMasterKeyBlock
			{
				Version = version,
				Iv = iv,
				Rounds = rounds,
				HashAlgorithm = hashAlgo,
				CipherAlgorithm = cipherAlgo,
				CipherTextLength = (uint)cipherText.Length,
				CipherText = cipherText
			};
		}

		public DpapiMasterKeyDecryptionResult DecryptWithKey(byte[] keyMaterial)
		{
			return DpapiMasterKeyCrypto.DecryptMasterKey(this, keyMaterial);
		}
	}

	internal sealed class DpapiMasterKeyDecryptionResult
	{
		public bool Success { get; init; }
		public string? FailureReason { get; init; }
		public byte[]? MasterKey { get; init; }
		public byte[]? MasterKeyHash { get; init; }
		public byte[]? HmacSalt { get; init; }
		public byte[]? Hmac { get; init; }
		public byte[]? HmacComputed { get; init; }
		public uint HashAlgorithm { get; init; }
		public uint CipherAlgorithm { get; init; }
		public uint Rounds { get; init; }
	}

	internal static class DpapiMasterKeyCrypto
	{
		private sealed class CryptoAlgorithm
		{
			public CryptoAlgorithm(uint id, string name, int keyLenBits, int ivLenBits, int blockLenBits, int digestLenBits, bool fixParity = false)
			{
				Id = id;
				Name = name;
				KeyLength = keyLenBits / 8;
				IvLength = ivLenBits / 8;
				BlockLength = blockLenBits / 8;
				DigestLength = digestLenBits / 8;
				FixParity = fixParity;
			}

			public uint Id { get; }
			public string Name { get; }
			public int KeyLength { get; }
			public int IvLength { get; }
			public int BlockLength { get; }
			public int DigestLength { get; }
			public bool FixParity { get; }
		}

		private static readonly Dictionary<uint, CryptoAlgorithm> Algorithms = new()
		{
			{ 0x6603, new CryptoAlgorithm(0x6603, "DES3", 192, 64, 64, 0, fixParity: true) },
			{ 0x6609, new CryptoAlgorithm(0x6609, "DES2", 128, 64, 64, 0, fixParity: true) },
			{ 0x6601, new CryptoAlgorithm(0x6601, "DES", 64, 64, 64, 0, fixParity: true) },
			{ 0x6611, new CryptoAlgorithm(0x6611, "AES", 128, 128, 128, 0) },
			{ 0x660e, new CryptoAlgorithm(0x660e, "AES-128", 128, 128, 128, 0) },
			{ 0x660f, new CryptoAlgorithm(0x660f, "AES-192", 192, 128, 128, 0) },
			{ 0x6610, new CryptoAlgorithm(0x6610, "AES-256", 256, 128, 128, 0) },
			{ 0x8003, new CryptoAlgorithm(0x8003, "MD5", 0, 0, 0, 128) },
			{ 0x8004, new CryptoAlgorithm(0x8004, "SHA1", 0, 0, 0, 160) },
			{ 0x800c, new CryptoAlgorithm(0x800c, "SHA256", 0, 0, 0, 256) },
			{ 0x800d, new CryptoAlgorithm(0x800d, "SHA384", 0, 0, 0, 384) },
			{ 0x800e, new CryptoAlgorithm(0x800e, "SHA512", 0, 0, 0, 512) },
			{ 0x8009, new CryptoAlgorithm(0x8009, "HMAC", 0, 0, 0, 160) }
		};

		public static DpapiMasterKeyFile ParseMasterKeyFile(byte[] raw)
		{
			return DpapiMasterKeyFile.Parse(raw);
		}

		public static DpapiMasterKeyFileDecryptionResult DecryptMasterKeyFile(byte[] raw, byte[] keyMaterial)
		{
			var file = DpapiMasterKeyFile.Parse(raw);
			return file.DecryptWithKey(keyMaterial);
		}

		internal static int GetCipherBlockLengthBytes(uint cipherAlgorithmId)
		{
			if (!Algorithms.TryGetValue(cipherAlgorithmId, out var algo))
				throw new InvalidDataException($"Unsupported cipher algorithm 0x{cipherAlgorithmId:x}.");
			if (algo.BlockLength <= 0)
				throw new InvalidDataException($"Algorithm 0x{cipherAlgorithmId:x} did not define a block size.");
			return algo.BlockLength;
		}

		internal static byte[] DecryptDpapiData(
			uint cipherAlgorithmId,
			uint hashAlgorithmId,
			byte[] cipherText,
			byte[] encKey,
			byte[] iv,
			uint rounds)
		{
			if (!Algorithms.TryGetValue(hashAlgorithmId, out var hashAlgo))
				throw new InvalidDataException($"Unsupported hash algorithm 0x{hashAlgorithmId:x}.");
			if (!Algorithms.TryGetValue(cipherAlgorithmId, out var cipherAlgo))
				throw new InvalidDataException($"Unsupported cipher algorithm 0x{cipherAlgorithmId:x}.");

			return DataDecrypt(cipherAlgo, hashAlgo, cipherText, encKey, iv, rounds);
		}

		public static DpapiMasterKeyDecryptionResult DecryptMasterKey(DpapiMasterKeyBlock block, byte[] keyMaterial)
		{
			if (block == null)
				throw new ArgumentNullException(nameof(block));
			if (keyMaterial == null || keyMaterial.Length == 0)
				return new DpapiMasterKeyDecryptionResult { Success = false, FailureReason = "Key material was empty." };

			if (!Algorithms.TryGetValue(block.HashAlgorithm, out var hashAlgo))
				return new DpapiMasterKeyDecryptionResult { Success = false, FailureReason = $"Unsupported hash algorithm 0x{block.HashAlgorithm:x}." };
			if (!Algorithms.TryGetValue(block.CipherAlgorithm, out var cipherAlgo))
				return new DpapiMasterKeyDecryptionResult { Success = false, FailureReason = $"Unsupported cipher algorithm 0x{block.CipherAlgorithm:x}." };

			if (block.CipherText.Length == 0)
				return new DpapiMasterKeyDecryptionResult { Success = false, FailureReason = "Ciphertext was empty." };

			byte[] clear;
			try
			{
				clear = DataDecrypt(cipherAlgo, hashAlgo, block.CipherText, keyMaterial, block.Iv, block.Rounds);
			}
			catch (Exception ex)
			{
				return new DpapiMasterKeyDecryptionResult
				{
					Success = false,
					FailureReason = $"Decrypt failed: {ex.Message}",
					HashAlgorithm = block.HashAlgorithm,
					CipherAlgorithm = block.CipherAlgorithm,
					Rounds = block.Rounds
				};
			}

			var hashLen = hashAlgo.DigestLength;
			if (clear.Length < 16 + hashLen + 64)
			{
				return new DpapiMasterKeyDecryptionResult
				{
					Success = false,
					FailureReason = "Decrypted data is too short.",
					HashAlgorithm = block.HashAlgorithm,
					CipherAlgorithm = block.CipherAlgorithm,
					Rounds = block.Rounds
				};
			}

			var hmacSalt = clear.AsSpan(0, 16).ToArray();
			var hmac = clear.AsSpan(16, hashLen).ToArray();
			var masterKey = clear.AsSpan(clear.Length - 64, 64).ToArray();
			var hmacComputed = ComputeHmac(hashAlgo, keyMaterial, hmacSalt, masterKey);

			var success = hmac.SequenceEqual(hmacComputed);
			var masterKeyHash = SHA1.HashData(masterKey);

			return new DpapiMasterKeyDecryptionResult
			{
				Success = success,
				FailureReason = success ? null : "HMAC validation failed.",
				MasterKey = success ? masterKey : null,
				MasterKeyHash = success ? masterKeyHash : null,
				HmacSalt = hmacSalt,
				Hmac = hmac,
				HmacComputed = hmacComputed,
				HashAlgorithm = block.HashAlgorithm,
				CipherAlgorithm = block.CipherAlgorithm,
				Rounds = block.Rounds
			};
		}

		private static byte[] DataDecrypt(
			CryptoAlgorithm cipherAlgo,
			CryptoAlgorithm hashAlgo,
			byte[] cipherText,
			byte[] encKey,
			byte[] iv,
			uint rounds)
		{
			var hashName = ResolveHashName(hashAlgo.Name);
			var derived = Pbkdf2Ms(encKey, iv, cipherAlgo.KeyLength + cipherAlgo.IvLength, checked((int)rounds), hashName);
			var key = derived.AsSpan(0, cipherAlgo.KeyLength).ToArray();
			var cipherIv = derived.AsSpan(cipherAlgo.KeyLength, cipherAlgo.IvLength).ToArray();

			if (cipherAlgo.FixParity)
				FixDesParity(key);

			return DecryptCbc(cipherAlgo.Name, key, cipherIv, cipherText);
		}

		private static byte[] ComputeHmac(CryptoAlgorithm hashAlgo, byte[] keyMaterial, byte[] hmacSalt, byte[] value)
		{
			var hashName = ResolveHashName(hashAlgo.Name);
			var encKey = Hmac(hashName, keyMaterial, hmacSalt);
			return Hmac(hashName, encKey, value);
		}

		private static byte[] Hmac(string hashName, byte[] key, byte[] data)
		{
			using var hmac = CreateHmac(hashName, key);
			return hmac.ComputeHash(data);
		}

		private static HMAC CreateHmac(string hashName, byte[] key)
		{
			return hashName switch
			{
				"MD5" => new HMACMD5(key),
				"SHA1" => new HMACSHA1(key),
				"SHA256" => new HMACSHA256(key),
				"SHA384" => new HMACSHA384(key),
				"SHA512" => new HMACSHA512(key),
				_ => new HMACSHA1(key)
			};
		}

		private static string ResolveHashName(string algoName)
		{
			return algoName.Equals("HMAC", StringComparison.OrdinalIgnoreCase)
				? "SHA1"
				: algoName.ToUpperInvariant();
		}

		private static byte[] DecryptCbc(string cipherName, byte[] key, byte[] iv, byte[] cipherText)
		{
			SymmetricAlgorithm algo = cipherName switch
			{
				"DES3" => TripleDES.Create(),
				"DES2" => TripleDES.Create(),
				"DES" => DES.Create(),
				"AES" => Aes.Create(),
				"AES-128" => Aes.Create(),
				"AES-192" => Aes.Create(),
				"AES-256" => Aes.Create(),
				_ => Aes.Create()
			};

			algo.Mode = CipherMode.CBC;
			algo.Padding = PaddingMode.None;
			algo.Key = key;
			algo.IV = iv;

			using var decryptor = algo.CreateDecryptor();
			return decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
		}

		private static byte[] Pbkdf2Ms(byte[] passphrase, byte[] salt, int keyLen, int iterations, string hashName)
		{
			if (iterations <= 0)
				throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be greater than zero.");

			var buffer = new List<byte>(keyLen);
			var blockIndex = 1;
			while (buffer.Count < keyLen)
			{
				var counter = new byte[4];
				BinaryPrimitives.WriteUInt32BigEndian(counter, (uint)blockIndex);
				blockIndex++;

				var uInput = new byte[salt.Length + counter.Length];
				Buffer.BlockCopy(salt, 0, uInput, 0, salt.Length);
				Buffer.BlockCopy(counter, 0, uInput, salt.Length, counter.Length);

				byte[] derived = Hmac(hashName, passphrase, uInput);
				for (int i = 1; i < iterations; i++)
				{
					var actual = Hmac(hashName, passphrase, derived);
					for (int j = 0; j < derived.Length; j++)
						derived[j] ^= actual[j];
				}

				buffer.AddRange(derived);
			}

			return buffer.Take(keyLen).ToArray();
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
