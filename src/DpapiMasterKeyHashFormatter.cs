using System;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class DpapiMasterKeyHashFormatter
	{
		// This mirrors SharpDPAPI's Dpapi.FormatHash() output so hashes can be used with John/Hashcat.
		internal static bool TryFormatDpapiMkHash(
			DpapiMasterKeyFile file,
			string sid,
			int context,
			out string guidWithBraces,
			out string hashText,
			out string failureReason)
		{
			guidWithBraces = string.Empty;
			hashText = string.Empty;
			failureReason = string.Empty;

			if (file == null)
			{
				failureReason = "Master key file was null.";
				return false;
			}

			if (string.IsNullOrWhiteSpace(sid))
			{
				failureReason = "SID was empty.";
				return false;
			}

			if (file.MasterKey == null)
			{
				failureReason = "Master key block not present.";
				return false;
			}

			var guid = file.Guid?.ToString() ?? file.GuidText?.Trim().Trim('{', '}');
			if (string.IsNullOrWhiteSpace(guid))
			{
				failureReason = "Master key GUID missing from header.";
				return false;
			}

			var block = file.MasterKey;
			if (!TryResolveAlgorithm(block.CipherAlgorithm, block.HashAlgorithm, out var version, out var cipherAlgo, out var hmacAlgo, out failureReason))
				return false;

			var saltHex = ToHexLower(block.Iv);
			var encDataHex = ToHexLower(block.CipherText);
			var encHexLen = checked(block.CipherText.Length * 2);

			guidWithBraces = "{" + guid + "}";
			hashText = $"$DPAPImk${version}*{context}*{sid}*{cipherAlgo}*{hmacAlgo}*{block.Rounds}*{saltHex}*{encHexLen}*{encDataHex}";
			return true;
		}

		private static bool TryResolveAlgorithm(
			uint cipherAlgorithmId,
			uint hashAlgorithmId,
			out int version,
			out string cipherAlgo,
			out string hmacAlgo,
			out string failureReason)
		{
			// Keep parity with SharpDPAPI's supported algorithm set.
			//
			// - AES-256 with SHA512 or SHA1: DPAPImk v2 / aes256 / sha512
			// - DES3 with HMAC: DPAPImk v1 / des3 / sha1
			if (cipherAlgorithmId == 26128 && (hashAlgorithmId == 32782 || hashAlgorithmId == 32772))
			{
				version = 2;
				cipherAlgo = "aes256";
				hmacAlgo = "sha512";
				failureReason = string.Empty;
				return true;
			}

			if (cipherAlgorithmId == 26115 && hashAlgorithmId == 32777)
			{
				version = 1;
				cipherAlgo = "des3";
				hmacAlgo = "sha1";
				failureReason = string.Empty;
				return true;
			}

			version = 0;
			cipherAlgo = string.Empty;
			hmacAlgo = string.Empty;
			failureReason = $"Alg crypt '{cipherAlgorithmId} / 0x{cipherAlgorithmId:X8}' with hash '{hashAlgorithmId} / 0x{hashAlgorithmId:X8}' not currently supported.";
			return false;
		}

		private static string ToHexLower(byte[] bytes)
		{
			if (bytes == null || bytes.Length == 0)
				return string.Empty;

			var chars = new char[bytes.Length * 2];
			var c = 0;
			for (int i = 0; i < bytes.Length; i++)
			{
				var b = bytes[i];
				chars[c++] = GetHexLowerChar(b >> 4);
				chars[c++] = GetHexLowerChar(b & 0x0f);
			}

			return new string(chars);
		}

		private static char GetHexLowerChar(int nibble)
		{
			return (char)(nibble < 10 ? ('0' + nibble) : ('a' + (nibble - 10)));
		}
	}
}

