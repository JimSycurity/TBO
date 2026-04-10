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

		/// <summary>
		/// The type of password hash this candidate's prekey was derived from. Values match the
		/// <c>hash_type</c> column of the <c>verified_password_hashes</c> cache table:
		/// <c>"sha1_pwd"</c> (SHA-1 of the UTF-16 password) or <c>"nt_pwd"</c> (MD4 of the UTF-16 password, aka NT hash).
		/// <see langword="null"/> for candidates whose source hash is not (yet) tracked.
		/// </summary>
		public string? SourceHashType { get; init; }

		/// <summary>
		/// The raw bytes of the source hash identified by <see cref="SourceHashType"/>. On a successful
		/// decrypt, callers should persist this to the verified-hash cache so future runs can skip
		/// re-deriving from plaintext. <see langword="null"/> when <see cref="SourceHashType"/> is unknown.
		/// </summary>
		public byte[]? SourceHash { get; init; }
	}

	/// <summary>
	/// String constants for <see cref="DpapiKeyMaterialCandidate.SourceHashType"/> and the cache
	/// table's <c>hash_type</c> column. Kept as constants rather than an enum so callers/storage
	/// can round-trip the raw string without a switch/enum dependency.
	/// </summary>
	internal static class DpapiVerifiedHashTypes
	{
		/// <summary>SHA-1 hash of the UTF-16 encoded user password (20 bytes).</summary>
		public const string Sha1Pwd = "sha1_pwd";

		/// <summary>NT hash — MD4 of the UTF-16 encoded user password (16 bytes).</summary>
		public const string NtPwd = "nt_pwd";
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

			byte[]? sha1Password = null;
			if (password != null)
			{
				var passwordUtf16 = Encoding.Unicode.GetBytes(password);
				sha1Password = SHA1.HashData(passwordUtf16);

				// If the caller didn't supply an NT hash, derive it from the password to cover domain-style keys too.
				if (ntHash == null)
				{
					ntHash = Titanis.Crypto.SlimHashAlgorithm
						.ComputeHash<Titanis.Crypto.Md4Context>(passwordUtf16);
				}
			}

			return DerivePreKeyCandidatesFromHashes(userSid, sha1Password, ntHash);
		}

		/// <summary>
		/// Builds candidates directly from pre-computed password hashes — used by both the plaintext
		/// entry point above and the verified-hash cache reader path in <c>Get-TBODpapi*</c> cmdlets.
		/// Each returned candidate is stamped with its <c>SourceHashType</c>/<c>SourceHash</c> so that
		/// a downstream successful decrypt can round-trip the winning hash into the cache.
		/// </summary>
		internal static IReadOnlyList<DpapiKeyMaterialCandidate> DerivePreKeyCandidatesFromHashes(
			string userSid,
			byte[]? sha1Password,
			byte[]? ntHash)
		{
			if (string.IsNullOrWhiteSpace(userSid))
				return Array.Empty<DpapiKeyMaterialCandidate>();

			sha1Password = (sha1Password != null && sha1Password.Length > 0) ? sha1Password : null;
			ntHash = (ntHash != null && ntHash.Length > 0) ? ntHash : null;

			var candidates = new List<DpapiKeyMaterialCandidate>();

			if (sha1Password != null)
			{
				var localPreKey = DeriveLocalPreKeyFromHash(userSid, sha1Password);
				candidates.Add(new DpapiKeyMaterialCandidate
				{
					Label = "Local: HMAC-SHA1(SHA1(password), SID\\0)",
					KeyMaterial = localPreKey,
					Confidence = 0.9,
					SourceHashType = DpapiVerifiedHashTypes.Sha1Pwd,
					SourceHash = (byte[])sha1Password.Clone(),
				});

				var localPreKeyNoNull = DeriveLocalPreKeyFromHashNoTerminator(userSid, sha1Password);
				candidates.Add(new DpapiKeyMaterialCandidate
				{
					Label = "Local: HMAC-SHA1(SHA1(password), SID)",
					KeyMaterial = localPreKeyNoNull,
					Confidence = 0.85,
					SourceHashType = DpapiVerifiedHashTypes.Sha1Pwd,
					SourceHash = (byte[])sha1Password.Clone(),
				});
			}

			if (ntHash != null)
			{
				// Local-account fallback when only NT hash is known (no plaintext SHA1(password)):
				// prekey = HMAC-SHA1(SHA1(NT), SID\0).
				var localFromNt = DeriveLocalPreKeyFromNtHash(userSid, ntHash);
				candidates.Add(new DpapiKeyMaterialCandidate
				{
					Label = "Local: HMAC-SHA1(SHA1(NT), SID\\0)",
					KeyMaterial = localFromNt,
					Confidence = 0.8,
					SourceHashType = DpapiVerifiedHashTypes.NtPwd,
					SourceHash = (byte[])ntHash.Clone(),
				});

				var localFromNtNoNull = DeriveLocalPreKeyFromNtHashNoTerminator(userSid, ntHash);
				candidates.Add(new DpapiKeyMaterialCandidate
				{
					Label = "Local: HMAC-SHA1(SHA1(NT), SID)",
					KeyMaterial = localFromNtNoNull,
					Confidence = 0.75,
					SourceHashType = DpapiVerifiedHashTypes.NtPwd,
					SourceHash = (byte[])ntHash.Clone(),
				});

				// Domain-style DPAPI: derive a 16-byte credkey via PBKDF2-HMAC-SHA256(ntHash, sid, ...),
				// then prekey = HMAC-SHA1(credkey, sid\0).
				var domainPreKey = DeriveDomainPreKeyFromNtHash(userSid, ntHash);
				candidates.Add(new DpapiKeyMaterialCandidate
				{
					Label = "Domain: HMAC-SHA1(PBKDF2-SHA256(NT), SID)",
					KeyMaterial = domainPreKey,
					Confidence = 0.9,
					SourceHashType = DpapiVerifiedHashTypes.NtPwd,
					SourceHash = (byte[])ntHash.Clone(),
				});

				// Fallback candidate sometimes referenced in tooling.
				var ntHashHmac = DeriveFallbackPreKeyFromNtHash(userSid, ntHash);
				candidates.Add(new DpapiKeyMaterialCandidate
				{
					Label = "Fallback: HMAC-SHA1(NT, SID\\0)",
					KeyMaterial = ntHashHmac,
					Confidence = 0.3,
					SourceHashType = DpapiVerifiedHashTypes.NtPwd,
					SourceHash = (byte[])ntHash.Clone(),
				});

				var ntHashHmacNoNull = DeriveFallbackPreKeyFromNtHashNoTerminator(userSid, ntHash);
				candidates.Add(new DpapiKeyMaterialCandidate
				{
					Label = "Fallback: HMAC-SHA1(NT, SID)",
					KeyMaterial = ntHashHmacNoNull,
					Confidence = 0.25,
					SourceHashType = DpapiVerifiedHashTypes.NtPwd,
					SourceHash = (byte[])ntHash.Clone(),
				});
			}

			return Deduplicate(candidates);
		}

		internal static byte[] DeriveLocalPreKeyFromHash(string userSid, byte[] passwordHash)
		{
			var sidUtf16Final = EncodeSidUtf16WithNullTerminator(userSid);
			return HmacSha1(passwordHash, sidUtf16Final);
		}

		internal static byte[] DeriveLocalPreKeyFromHashNoTerminator(string userSid, byte[] passwordHash)
		{
			var sidUtf16 = Encoding.Unicode.GetBytes(userSid);
			return HmacSha1(passwordHash, sidUtf16);
		}

		internal static byte[] DeriveLocalPreKeyFromNtHash(string userSid, byte[] ntHash)
		{
			var ntAsSha1 = SHA1.HashData(ntHash);
			return DeriveLocalPreKeyFromHash(userSid, ntAsSha1);
		}

		internal static byte[] DeriveLocalPreKeyFromNtHashNoTerminator(string userSid, byte[] ntHash)
		{
			var ntAsSha1 = SHA1.HashData(ntHash);
			return DeriveLocalPreKeyFromHashNoTerminator(userSid, ntAsSha1);
		}

		internal static byte[] DeriveDomainPreKeyFromNtHash(string userSid, byte[] ntHash)
		{
			var sidUtf16 = Encoding.Unicode.GetBytes(userSid);
			var sidUtf16Final = EncodeSidUtf16WithNullTerminator(sidUtf16);

			var credKey = DeriveCredKeyFromNtHash(ntHash, sidUtf16);
			return HmacSha1(credKey, sidUtf16Final);
		}

		internal static byte[] DeriveFallbackPreKeyFromNtHash(string userSid, byte[] ntHash)
		{
			var sidUtf16Final = EncodeSidUtf16WithNullTerminator(userSid);
			return HmacSha1(ntHash, sidUtf16Final);
		}

		internal static byte[] DeriveFallbackPreKeyFromNtHashNoTerminator(string userSid, byte[] ntHash)
		{
			var sidUtf16 = Encoding.Unicode.GetBytes(userSid);
			return HmacSha1(ntHash, sidUtf16);
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

		private static byte[] EncodeSidUtf16WithNullTerminator(string userSid)
		{
			var sidUtf16 = Encoding.Unicode.GetBytes(userSid);
			return EncodeSidUtf16WithNullTerminator(sidUtf16);
		}

		private static byte[] EncodeSidUtf16WithNullTerminator(byte[] sidUtf16)
		{
			var sidUtf16Final = new byte[sidUtf16.Length + 2]; // include UTF-16 NUL terminator
			Buffer.BlockCopy(sidUtf16, 0, sidUtf16Final, 0, sidUtf16.Length);
			return sidUtf16Final;
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
