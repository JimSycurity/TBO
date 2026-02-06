using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed record DpapiKeyMaterialCandidate
	{
		public string Label { get; init; } = string.Empty;
		public byte[] KeyMaterial { get; init; } = Array.Empty<byte>();
		public double Confidence { get; init; }
	}

	internal static class DpapiUserKeyDerivation
	{
		// DPAPI user master key protection uses "prekey" material derived from SID + password/NT hash.
		// We generate multiple candidates (local + domain patterns) and rely on master key HMAC validation
		// to identify the correct one.
		internal static IReadOnlyList<DpapiKeyMaterialCandidate> DerivePreKeyCandidates(
			string userSid,
			string? password,
			byte[]? ntHash)
		{
			if (string.IsNullOrWhiteSpace(userSid))
				return Array.Empty<DpapiKeyMaterialCandidate>();

			password = string.IsNullOrWhiteSpace(password) ? null : password;
			ntHash = (ntHash != null && ntHash.Length > 0) ? ntHash : null;

			var sidUtf16 = Encoding.Unicode.GetBytes(userSid);
			var sidUtf16Final = new byte[sidUtf16.Length + 2]; // include UTF-16 NUL terminator
			Buffer.BlockCopy(sidUtf16, 0, sidUtf16Final, 0, sidUtf16.Length);

			var candidates = new List<DpapiKeyMaterialCandidate>();

			if (password != null)
			{
				var passwordUtf16 = Encoding.Unicode.GetBytes(password);
				var sha1Password = SHA1.HashData(passwordUtf16);
				var localPreKey = HmacSha1(sha1Password, sidUtf16Final);
				candidates.Add(new DpapiKeyMaterialCandidate
				{
					Label = "Local: HMAC-SHA1(SHA1(password), SID)",
					KeyMaterial = localPreKey,
					Confidence = 0.9
				});

				// If the caller didn't supply an NT hash, derive it from the password to cover domain-style keys too.
				if (ntHash == null)
				{
					ntHash = Titanis.Crypto.SlimHashAlgorithm
						.ComputeHash<Titanis.Crypto.Md4Context>(passwordUtf16);
				}
			}

			if (ntHash != null && ntHash.Length > 0)
			{
				// Domain-style DPAPI: derive a 16-byte credkey via PBKDF2-HMAC-SHA256(ntHash, sid, ...),
				// then prekey = HMAC-SHA1(credkey, sid\0).
				var credKey = DeriveCredKeyFromNtHash(ntHash, sidUtf16);
				var domainPreKey = HmacSha1(credKey, sidUtf16Final);
				candidates.Add(new DpapiKeyMaterialCandidate
				{
					Label = "Domain: HMAC-SHA1(PBKDF2-SHA256(NT), SID)",
					KeyMaterial = domainPreKey,
					Confidence = 0.9
				});

				// Fallback candidate sometimes referenced in tooling.
				var ntHashHmac = HmacSha1(ntHash, sidUtf16Final);
				candidates.Add(new DpapiKeyMaterialCandidate
				{
					Label = "Fallback: HMAC-SHA1(NT, SID)",
					KeyMaterial = ntHashHmac,
					Confidence = 0.3
				});
			}

			return Deduplicate(candidates);
		}

		private static byte[] DeriveCredKeyFromNtHash(byte[] ntHash, byte[] sidUtf16)
		{
			var tmp = Rfc2898DeriveBytes.Pbkdf2(
				password: ntHash,
				salt: sidUtf16,
				iterations: 10000,
				hashAlgorithm: HashAlgorithmName.SHA256,
				outputLength: 32);

			return Rfc2898DeriveBytes.Pbkdf2(
				password: tmp,
				salt: sidUtf16,
				iterations: 1,
				hashAlgorithm: HashAlgorithmName.SHA256,
				outputLength: 16);
		}

		private static byte[] HmacSha1(byte[] key, byte[] data)
		{
			using var hmac = new HMACSHA1(key);
			return hmac.ComputeHash(data);
		}

		private static IReadOnlyList<DpapiKeyMaterialCandidate> Deduplicate(List<DpapiKeyMaterialCandidate> candidates)
		{
			var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			var results = new List<DpapiKeyMaterialCandidate>(candidates.Count);

			foreach (var candidate in candidates)
			{
				if (candidate.KeyMaterial == null || candidate.KeyMaterial.Length == 0)
					continue;

				var key = Convert.ToHexString(candidate.KeyMaterial);
				if (!seen.Add(key))
					continue;

				results.Add(candidate);
			}

			return results
				.OrderByDescending(c => c.Confidence)
				.ThenBy(c => c.Label, StringComparer.OrdinalIgnoreCase)
				.ToList();
		}
	}
}

