using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Titanis.Tbo.Smb2.PowerShell
{
	/// <summary>
	/// Windows Hello / NGC PIN helpers (smartCardSecret) used for decrypting PIN-protected Crypto\Keys blobs.
	/// </summary>
	/// <remarks>
	/// Some Windows Hello private key DPAPI blobs require additional entropy derived from the PIN.
	/// Tooling often refers to this derived material as "smartCardSecret" (dpapick3).
	/// </remarks>
	internal static class NgcPinCrypto
	{
		private sealed record PinBytesCandidate(string Label, byte[] Bytes);

		private sealed record Pbkdf2Candidate(string Label, HashAlgorithmName HashAlgorithm, int OutputLength);

		internal static bool TryDecryptDpapiBlobWithPin(
			DpapiBlob blob,
			byte[] masterKey,
			byte[] cngEntropy,
			string pin,
			byte[] pbkdf2Salt,
			int pbkdf2Rounds,
			out byte[] cleartext,
			out string? failureReason)
		{
			cleartext = Array.Empty<byte>();
			failureReason = null;

			if (blob == null)
			{
				failureReason = "DPAPI blob was null.";
				return false;
			}

			if (masterKey == null || masterKey.Length == 0)
			{
				failureReason = "Master key material was empty.";
				return false;
			}

			if (string.IsNullOrWhiteSpace(pin))
			{
				failureReason = "PIN was empty.";
				return false;
			}

			if (pbkdf2Salt == null || pbkdf2Salt.Length == 0)
			{
				failureReason = "PBKDF2 salt was empty.";
				return false;
			}

			if (pbkdf2Rounds <= 0)
			{
				failureReason = "PBKDF2 rounds must be greater than zero.";
				return false;
			}

			// Candidate generation is intentionally conservative: try the most likely forms first,
			// but fall back to a few variants because the PIN-to-bytes encoding and PBKDF2 PRF
			// differ across tooling and observed artifacts.
			var pinCandidates = new List<PinBytesCandidate>
			{
				new("UTF-16LE", Encoding.Unicode.GetBytes(pin)),
				new("UTF-16LE-NUL", AppendNullTerminatorUtf16(pin)),
				new("UTF-8", Encoding.UTF8.GetBytes(pin))
			};

			var pbkdf2Candidates = new List<Pbkdf2Candidate>
			{
				new("PBKDF2-SHA256-32", HashAlgorithmName.SHA256, 32),
				new("PBKDF2-SHA1-32", HashAlgorithmName.SHA1, 32),
				new("PBKDF2-SHA512-32", HashAlgorithmName.SHA512, 32),
				new("PBKDF2-SHA512-64", HashAlgorithmName.SHA512, 64)
			};

			// Decrypt attempts: "CNG entropy" is the baseline for CNG key DPAPI blobs, and the
			// PIN-derived material is typically appended. We also try a couple alternates to be robust.
			var entropyBuilders = new (string Label, Func<byte[], byte[]> Build)[]
			{
				("CNG+SCS", smartCardSecret => Combine(cngEntropy, smartCardSecret)),
				("SCS+CNG", smartCardSecret => Combine(smartCardSecret, cngEntropy)),
				("SCS", smartCardSecret => smartCardSecret)
			};

			var attempted = new List<string>();

			foreach (var pinCandidate in pinCandidates)
			{
				foreach (var pbkdf2Candidate in pbkdf2Candidates)
				{
					byte[] smartCardSecret;
					try
					{
						smartCardSecret = Rfc2898DeriveBytes.Pbkdf2(
							password: pinCandidate.Bytes,
							salt: pbkdf2Salt,
							iterations: pbkdf2Rounds,
							hashAlgorithm: pbkdf2Candidate.HashAlgorithm,
							outputLength: pbkdf2Candidate.OutputLength);
					}
					catch (Exception ex)
					{
						attempted.Add($"{pinCandidate.Label}/{pbkdf2Candidate.Label} (derive failed: {ex.Message})");
						continue;
					}

					foreach (var entropyBuilder in entropyBuilders)
					{
						var entropy = entropyBuilder.Build(smartCardSecret);
						var result = DpapiBlobCrypto.Decrypt(blob, masterKey, entropy);
						if (result.Success && result.Cleartext != null && result.Cleartext.Length > 0)
						{
							cleartext = result.Cleartext;
							return true;
						}

						attempted.Add($"{pinCandidate.Label}/{pbkdf2Candidate.Label}/{entropyBuilder.Label}");
					}
				}
			}

			failureReason = attempted.Count == 0
				? "PIN-based DPAPI decrypt failed (no candidates attempted)."
				: "PIN-based DPAPI decrypt failed. Tried: " + string.Join(", ", attempted.Take(12)) + (attempted.Count > 12 ? ", ..." : string.Empty);
			return false;
		}

		private static byte[] AppendNullTerminatorUtf16(string value)
		{
			var bytes = Encoding.Unicode.GetBytes(value);
			var padded = new byte[bytes.Length + 2];
			Buffer.BlockCopy(bytes, 0, padded, 0, bytes.Length);
			return padded;
		}

		private static byte[] Combine(params byte[]?[] parts)
		{
			int total = 0;
			foreach (var part in parts)
			{
				if (part == null || part.Length == 0)
					continue;
				total += part.Length;
			}

			if (total == 0)
				return Array.Empty<byte>();

			var combined = new byte[total];
			int offset = 0;
			foreach (var part in parts)
			{
				if (part == null || part.Length == 0)
					continue;
				Buffer.BlockCopy(part, 0, combined, offset, part.Length);
				offset += part.Length;
			}

			return combined;
		}
	}
}

