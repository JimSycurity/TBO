using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading;
using Titanis;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboNgcProtectorInfo
	{
		public string ProtectorId { get; init; } = string.Empty;
		public string? Provider { get; init; }
		public string? KeyName { get; init; }
		public DateTime? TimestampUtc { get; init; }
		public int? DataLength { get; init; }
		public string? DataHex { get; init; }
		public bool IsTpmProtected { get; init; }
		public string? FailureReason { get; init; }
	}

	public sealed class TboNgcItemInfo
	{
		public string ItemGroupId { get; init; } = string.Empty;
		public string ItemId { get; init; } = string.Empty;
		public string? Name { get; init; }
		public string? Provider { get; init; }
		public string? KeyName { get; init; }
		public string? FailureReason { get; init; }
	}

	public sealed class TboNgcInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string ShareName { get; init; } = string.Empty;
		public string RootPath { get; init; } = string.Empty;

		public string NgcGuid { get; init; } = string.Empty;
		public string? UserSid { get; init; }
		public string? MainProvider { get; init; }

		// Common values referenced by Windows Hello / NGC PIN decryption tooling.
		public string? KeyStorageProviderGuid1 { get; init; }
		public int? InputDataLength { get; init; }
		public string? InputDataHex { get; init; }
		public string? KeyStorageProviderGuid2 { get; init; }

		public int ProtectorCount { get; init; }
		public int ItemCount { get; init; }

		public TboNgcProtectorInfo[]? Protectors { get; init; }
		public TboNgcItemInfo[]? Items { get; init; }

		public string? FailureReason { get; init; }
	}

	internal static class NgcHelpers
	{
		internal const string DefaultShareName = "C$";
		internal const string DefaultNgcRootRelativePath = @"Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc";

		internal const string MsSoftwareKeyStorageProvider = "Microsoft Software Key Storage Provider";
		internal const string MsPlatformCryptoProvider = "Microsoft Platform Crypto Provider";

		// This appears as an item name in the NGC container and is used by common tooling to locate GUID2.
		internal const string Guid2MarkerItemName = "//9DDC52DB-DC02-4A8C-B892-38DEF4FA748F";

		internal static string NormalizeServerName(string? serverName)
			=> DpapiHelpers.NormalizeServerName(serverName);

		internal static string NormalizeShareName(string? shareName)
			=> DpapiHelpers.NormalizeShareName(shareName);

		internal static bool IsMissingPath(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_NAME_INVALID;
		}

		internal static bool IsAccessDenied(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_ACCESS_DENIED
				or Ntstatus.STATUS_PRIVILEGE_NOT_HELD;
		}

		internal static string DecodeUtf16FileBytes(byte[] data)
		{
			if (data.Length == 0)
				return string.Empty;

			return Encoding.Unicode
				.GetString(data)
				.TrimEnd('\0')
				.Replace("\0", string.Empty);
		}

		internal static DateTime? TryParseFileTimeUtc(byte[] data)
		{
			if (data.Length < 8)
				return null;

			try
			{
				var fileTime = BinaryPrimitives.ReadInt64LittleEndian(data);
				return DateTime.FromFileTimeUtc(fileTime);
			}
			catch
			{
				return null;
			}
		}

		internal static string PrefixSnapshot(string? snapshot, string shareRelativePath, string snapshotParamName)
		{
			if (string.IsNullOrWhiteSpace(snapshot))
				return shareRelativePath;

			var trimmed = snapshot.Trim().Trim('\\');
			if (!trimmed.StartsWith("@GMT-", StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException("Snapshot must be an @GMT- token (ex: @GMT-2026.02.09-12.00.00).", snapshotParamName);

			return $@"{trimmed}\{shareRelativePath}";
		}
	}

	internal static class NgcLocator
	{
		internal static IEnumerable<TboNgcInfo> Enumerate(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			string? snapshot,
			bool includeProtectors,
			bool includeItems,
			bool includeProtectorData,
			Action<string> writeVerbose,
			Action<string> writeWarning,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			var fileSystem = SmbFileSystemResolver.Resolve(smb);

			var rootRel = NgcHelpers.PrefixSnapshot(snapshot, NgcHelpers.DefaultNgcRootRelativePath, "Snapshot");
			var root = new UncPath(serverName, shareName, rootRel);

			ISmbDirectory? rootDir = null;
			try
			{
				rootDir = fileSystem.OpenDirectory(root, cancellationToken);
			}
			catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
			{
				writeVerbose($"Get-TBONGCInfo could not open {root}: {ex.StatusCode}.");
				yield break;
			}
			catch (NtstatusException ex) when (NgcHelpers.IsAccessDenied(ex))
			{
				writeWarning($"Get-TBONGCInfo was denied access to {root}: {ex.StatusCode}.");
				yield break;
			}
			catch (Exception ex)
			{
				logException($"Get-TBONGCInfo failed to open {root}", ex);
				yield break;
			}

			using (rootDir)
			{
				var entries = rootDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken);
				foreach (var entry in entries)
				{
					cancellationToken.ThrowIfCancellationRequested();

					if (string.IsNullOrEmpty(entry.FileName) || entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (!isDirectory || isReparse)
						continue;

					if (!Guid.TryParse(entry.FileName, out _))
						continue;

					yield return ParseContainer(
						smb,
						serverName,
						shareName,
						snapshot,
						entry.FileName,
						includeProtectors,
						includeItems,
						includeProtectorData,
						writeVerbose,
						writeWarning,
						logException,
						cancellationToken);
				}
			}
		}

		private static TboNgcInfo ParseContainer(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			string? snapshot,
			string ngcGuid,
			bool includeProtectors,
			bool includeItems,
			bool includeProtectorData,
			Action<string> writeVerbose,
			Action<string> writeWarning,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			var baseRel = $@"{NgcHelpers.DefaultNgcRootRelativePath}\{ngcGuid}";
			var containerRootRel = NgcHelpers.PrefixSnapshot(snapshot, baseRel, "Snapshot");
			var containerRoot = new UncPath(serverName, shareName, containerRootRel);

			try
			{
				string? userSid = null;
				string? mainProvider = null;

				try
				{
					var sidBytes = DpapiHelpers.ReadFileBytes(smb, new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, $@"{baseRel}\1.dat", "Snapshot")), cancellationToken);
					userSid = NgcHelpers.DecodeUtf16FileBytes(sidBytes);
				}
				catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
				{
					userSid = null;
				}

				try
				{
					var providerBytes = DpapiHelpers.ReadFileBytes(smb, new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, $@"{baseRel}\7.dat", "Snapshot")), cancellationToken);
					mainProvider = NgcHelpers.DecodeUtf16FileBytes(providerBytes);
				}
				catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
				{
					mainProvider = null;
				}

				var protectors = ParseProtectors(
					smb,
					serverName,
					shareName,
					snapshot,
					baseRel,
					includeProtectorData,
					writeVerbose,
					writeWarning,
					logException,
					cancellationToken);

				var items = ParseItems(
					smb,
					serverName,
					shareName,
					snapshot,
					baseRel,
					writeVerbose,
					writeWarning,
					logException,
					cancellationToken);

				// Derived values used by common Windows Hello PIN decryption flows.
				var pinProtector = protectors.FirstOrDefault(x =>
					x.Provider != null
					&& (x.Provider.Equals(NgcHelpers.MsSoftwareKeyStorageProvider, StringComparison.OrdinalIgnoreCase)
						|| x.Provider.Equals(NgcHelpers.MsPlatformCryptoProvider, StringComparison.OrdinalIgnoreCase)));
				var guid1 = pinProtector?.KeyName;
				var inputData = pinProtector?.DataHex;
				var inputLen = pinProtector?.DataLength;

				var guid2 = items
					.FirstOrDefault(x => x.Name != null && x.Name.Equals(NgcHelpers.Guid2MarkerItemName, StringComparison.OrdinalIgnoreCase))
					?.KeyName;

				return new TboNgcInfo
				{
					ServerName = serverName,
					ShareName = shareName,
					RootPath = containerRoot.ToString(),
					NgcGuid = ngcGuid,
					UserSid = userSid,
					MainProvider = mainProvider,
					KeyStorageProviderGuid1 = guid1,
					InputDataLength = inputLen,
					InputDataHex = inputData,
					KeyStorageProviderGuid2 = guid2,
					ProtectorCount = protectors.Count,
					ItemCount = items.Count,
					Protectors = includeProtectors ? protectors.ToArray() : null,
					Items = includeItems ? items.ToArray() : null,
					FailureReason = null
				};
			}
			catch (Exception ex)
			{
				logException($"Get-TBONGCInfo failed to parse {containerRoot}", ex);
				return new TboNgcInfo
				{
					ServerName = serverName,
					ShareName = shareName,
					RootPath = containerRoot.ToString(),
					NgcGuid = ngcGuid,
					FailureReason = ex.Message
				};
			}
		}

		private static List<TboNgcProtectorInfo> ParseProtectors(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			string? snapshot,
			string baseRel,
			bool includeProtectorData,
			Action<string> writeVerbose,
			Action<string> writeWarning,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			var results = new List<TboNgcProtectorInfo>();
			var fileSystem = SmbFileSystemResolver.Resolve(smb);

			var protectorsRel = $@"{baseRel}\Protectors";
			var protectorsDirPath = new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, protectorsRel, "Snapshot"));

			ISmbDirectory? protectorsDir = null;
			try
			{
				protectorsDir = fileSystem.OpenDirectory(protectorsDirPath, cancellationToken);
			}
			catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
			{
				return results;
			}
			catch (NtstatusException ex) when (NgcHelpers.IsAccessDenied(ex))
			{
				writeWarning($"Get-TBONGCInfo was denied access to {protectorsDirPath}: {ex.StatusCode}.");
				return results;
			}
			catch (Exception ex)
			{
				logException($"Get-TBONGCInfo failed to open {protectorsDirPath}", ex);
				return results;
			}

			using (protectorsDir)
			{
				var entries = protectorsDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken);
				foreach (var entry in entries)
				{
					cancellationToken.ThrowIfCancellationRequested();

					if (string.IsNullOrEmpty(entry.FileName) || entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (!isDirectory || isReparse)
						continue;

					var protectorId = entry.FileName;
					results.Add(ParseProtector(
						smb,
						serverName,
						shareName,
						snapshot,
						baseRel,
						protectorId,
						includeProtectorData,
						writeVerbose,
						writeWarning,
						logException,
						cancellationToken));
				}
			}

			return results;
		}

		private static TboNgcProtectorInfo ParseProtector(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			string? snapshot,
			string baseRel,
			string protectorId,
			bool includeProtectorData,
			Action<string> writeVerbose,
			Action<string> writeWarning,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			var protectorRel = $@"{baseRel}\Protectors\{protectorId}";

			try
			{
				string? provider = null;
				string? keyName = null;
				DateTime? timestampUtc = null;
				byte[]? dataBytes = null;

				try
				{
					var bytes = DpapiHelpers.ReadFileBytes(smb, new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, $@"{protectorRel}\1.dat", "Snapshot")), cancellationToken);
					provider = NgcHelpers.DecodeUtf16FileBytes(bytes);
				}
				catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
				{
					provider = null;
				}

				try
				{
					var bytes = DpapiHelpers.ReadFileBytes(smb, new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, $@"{protectorRel}\2.dat", "Snapshot")), cancellationToken);
					keyName = NgcHelpers.DecodeUtf16FileBytes(bytes);
				}
				catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
				{
					keyName = null;
				}

				try
				{
					var bytes = DpapiHelpers.ReadFileBytes(smb, new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, $@"{protectorRel}\9.dat", "Snapshot")), cancellationToken);
					timestampUtc = NgcHelpers.TryParseFileTimeUtc(bytes);
				}
				catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
				{
					timestampUtc = null;
				}

				if (includeProtectorData)
				{
					try
					{
						dataBytes = DpapiHelpers.ReadFileBytes(smb, new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, $@"{protectorRel}\15.dat", "Snapshot")), cancellationToken);
					}
					catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
					{
						dataBytes = null;
					}
				}

				var isTpm = string.IsNullOrWhiteSpace(keyName);
				if (isTpm && provider != null && provider.Equals(NgcHelpers.MsPlatformCryptoProvider, StringComparison.OrdinalIgnoreCase))
					writeVerbose($"Get-TBONGCInfo protector {protectorId} appears TPM-backed (missing 2.dat).");

				return new TboNgcProtectorInfo
				{
					ProtectorId = protectorId,
					Provider = provider,
					KeyName = keyName,
					TimestampUtc = timestampUtc,
					DataLength = dataBytes?.Length,
					DataHex = dataBytes != null ? dataBytes.ToHexString() : null,
					IsTpmProtected = isTpm,
					FailureReason = null
				};
			}
			catch (Exception ex)
			{
				logException($"Get-TBONGCInfo failed to parse protector {protectorRel}", ex);
				return new TboNgcProtectorInfo
				{
					ProtectorId = protectorId,
					FailureReason = ex.Message
				};
			}
		}

		private static List<TboNgcItemInfo> ParseItems(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			string? snapshot,
			string baseRel,
			Action<string> writeVerbose,
			Action<string> writeWarning,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			var results = new List<TboNgcItemInfo>();
			var fileSystem = SmbFileSystemResolver.Resolve(smb);

			var containerDirPath = new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, baseRel, "Snapshot"));

			ISmbDirectory? containerDir = null;
			try
			{
				containerDir = fileSystem.OpenDirectory(containerDirPath, cancellationToken);
			}
			catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
			{
				return results;
			}
			catch (NtstatusException ex) when (NgcHelpers.IsAccessDenied(ex))
			{
				writeWarning($"Get-TBONGCInfo was denied access to {containerDirPath}: {ex.StatusCode}.");
				return results;
			}
			catch (Exception ex)
			{
				logException($"Get-TBONGCInfo failed to open {containerDirPath}", ex);
				return results;
			}

			using (containerDir)
			{
				var headEntries = containerDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken);
				foreach (var headEntry in headEntries)
				{
					cancellationToken.ThrowIfCancellationRequested();

					if (string.IsNullOrEmpty(headEntry.FileName) || headEntry.FileName is "." or "..")
						continue;

					bool isDirectory = (headEntry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (headEntry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (!isDirectory || isReparse)
						continue;

					if (!headEntry.FileName.StartsWith("{", StringComparison.OrdinalIgnoreCase))
						continue;

					var itemGroupId = headEntry.FileName;
					var itemGroupRel = $@"{baseRel}\{itemGroupId}";
					var itemGroupPath = new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, itemGroupRel, "Snapshot"));

					ISmbDirectory? itemGroupDir = null;
					try
					{
						itemGroupDir = fileSystem.OpenDirectory(itemGroupPath, cancellationToken);
					}
					catch
					{
						continue;
					}

					using (itemGroupDir)
					{
						var subEntries = itemGroupDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken);
						// Mirror tooling behavior: skip groups that only contain a single entry.
						if (subEntries.Count <= 1)
							continue;

						foreach (var subEntry in subEntries)
						{
							cancellationToken.ThrowIfCancellationRequested();

							if (string.IsNullOrEmpty(subEntry.FileName) || subEntry.FileName is "." or "..")
								continue;

							bool subIsDirectory = (subEntry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
							bool subIsReparse = (subEntry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
							if (!subIsDirectory || subIsReparse)
								continue;

							if (subEntry.FileName.StartsWith("{", StringComparison.OrdinalIgnoreCase))
								continue;

							results.Add(ParseItem(
								smb,
								serverName,
								shareName,
								snapshot,
								baseRel,
								itemGroupId,
								subEntry.FileName,
								writeVerbose,
								writeWarning,
								logException,
								cancellationToken));
						}
					}
				}
			}

			return results;
		}

		private static TboNgcItemInfo ParseItem(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			string? snapshot,
			string baseRel,
			string itemGroupId,
			string itemId,
			Action<string> writeVerbose,
			Action<string> writeWarning,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			var itemRel = $@"{baseRel}\{itemGroupId}\{itemId}";
			try
			{
				string? name = null;
				string? provider = null;
				string? keyName = null;

				try
				{
					var bytes = DpapiHelpers.ReadFileBytes(smb, new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, $@"{itemRel}\1.dat", "Snapshot")), cancellationToken);
					name = NgcHelpers.DecodeUtf16FileBytes(bytes);
				}
				catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
				{
					name = null;
				}

				try
				{
					var bytes = DpapiHelpers.ReadFileBytes(smb, new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, $@"{itemRel}\2.dat", "Snapshot")), cancellationToken);
					provider = NgcHelpers.DecodeUtf16FileBytes(bytes);
				}
				catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
				{
					provider = null;
				}

				try
				{
					var bytes = DpapiHelpers.ReadFileBytes(smb, new UncPath(serverName, shareName, NgcHelpers.PrefixSnapshot(snapshot, $@"{itemRel}\3.dat", "Snapshot")), cancellationToken);
					keyName = NgcHelpers.DecodeUtf16FileBytes(bytes);
				}
				catch (NtstatusException ex) when (NgcHelpers.IsMissingPath(ex))
				{
					keyName = null;
				}

				return new TboNgcItemInfo
				{
					ItemGroupId = itemGroupId,
					ItemId = itemId,
					Name = name,
					Provider = provider,
					KeyName = keyName,
					FailureReason = null
				};
			}
			catch (Exception ex)
			{
				logException($"Get-TBONGCInfo failed to parse item {itemRel}", ex);
				return new TboNgcItemInfo
				{
					ItemGroupId = itemGroupId,
					ItemId = itemId,
					FailureReason = ex.Message
				};
			}
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBONGCInfo")]
	[OutputType(typeof(TboNgcInfo))]
	public sealed class GetTBONGCInfo : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public string ShareName { get; set; } = NgcHelpers.DefaultShareName;

		[Parameter]
		public string? Snapshot { get; set; }

		[Parameter]
		public SwitchParameter IncludeProtectors { get; set; }

		[Parameter]
		public SwitchParameter IncludeItems { get; set; }

		[Parameter]
		public SwitchParameter IncludeProtectorData { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = NgcHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var shareName = NgcHelpers.NormalizeShareName(this.ShareName);
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("ShareName must be provided.", nameof(this.ShareName));

			var snapshot = string.IsNullOrWhiteSpace(this.Snapshot)
				? null
				: this.Snapshot.Trim();

			var results = NgcLocator.Enumerate(
				smb,
				serverName,
				shareName,
				snapshot,
				this.IncludeProtectors.IsPresent,
				this.IncludeItems.IsPresent,
				this.IncludeProtectorData.IsPresent,
				message => this.LogVerbose(smb, message),
				message => this.LogWarning(smb, message),
				(context, ex) => this.LogException(smb, context, ex, emitWarning: false),
				cancellationToken);

			foreach (var result in results)
			{
				this.WriteObject(result);
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}
	}
}
