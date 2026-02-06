using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Management.Automation;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboDpapiBlobInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Source { get; init; } = string.Empty;
		public string Path { get; init; } = string.Empty;
		public string? ValueName { get; init; }
		public RegistryValueType? ValueType { get; init; }
		public int? DataLength { get; init; }
		public long? FileSize { get; init; }
		public int MatchOffset { get; init; }
		public int BytesScanned { get; init; }
	}

	[Cmdlet(VerbsCommon.Find, "TBODpapiBlobs", DefaultParameterSetName = FileSystemParameterSet)]
	[OutputType(typeof(TboDpapiBlobInfo))]
	public sealed class FindTBODpapiBlobs : TboRegCmdlet
	{
		private const string FileSystemParameterSet = "FileSystem";
		private const string RegistryParameterSet = "Registry";
		private const int DefaultMaxBytes = 1024;

		[Parameter(Mandatory = true, Position = 1, ParameterSetName = FileSystemParameterSet, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 1, ParameterSetName = RegistryParameterSet, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string RegistryPath { get; set; } = string.Empty;

		[Parameter]
		public SwitchParameter Recurse { get; set; }

		[Parameter(ParameterSetName = FileSystemParameterSet)]
		public SwitchParameter FollowReparse { get; set; }

		[Parameter]
		[ValidateRange(1, int.MaxValue)]
		public int MaxBytes { get; set; } = DefaultMaxBytes;

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var serverName = DpapiHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			if (this.ParameterSetName == RegistryParameterSet)
			{
				FindRegistryBlobs(smb, serverName, cancellationToken);
				return;
			}

			FindFileSystemBlobs(smb, serverName, cancellationToken);
		}

		private void FindFileSystemBlobs(ISmbProviderInfo smb, string serverName, CancellationToken cancellationToken)
		{
			var targetPath = this.Path;
			if (string.IsNullOrWhiteSpace(targetPath))
				throw new ArgumentException("Path must be provided.", nameof(this.Path));

			var uncPath = ResolveToUncPath(targetPath, nameof(this.Path));
			if (string.IsNullOrEmpty(uncPath.ShareName))
				throw new ArgumentException($"Path must include a share name: {uncPath}", nameof(this.Path));

			if (!string.IsNullOrEmpty(uncPath.ServerName)
				&& !uncPath.ServerName.Equals(serverName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"ServerName '{serverName}' does not match UNC host '{uncPath.ServerName}'.", nameof(this.ServerName));

			var progressId = 42;
			var progressActivity = $"Scanning for DPAPI blobs on {serverName}";
			this.WriteProgressUpdate(progressId, progressActivity, $"Scanning {uncPath}");

			var fileSystem = SmbFileSystemResolver.Resolve(smb);
			ScanFileSystemPath(smb, fileSystem, uncPath, progressId, progressActivity, cancellationToken);

			this.WriteProgress(new ProgressRecord(progressId, progressActivity, "Completed")
			{
				RecordType = ProgressRecordType.Completed
			});
		}

		private void FindRegistryBlobs(ISmbProviderInfo smb, string serverName, CancellationToken cancellationToken)
		{
			var parsed = ParseRegistryPath(this.RegistryPath, nameof(this.RegistryPath));
			var access = RegistryAccessRights.QueryValue;
			if (this.Recurse.IsPresent)
				access |= RegistryAccessRights.EnumerateSubkeys;

			var progressId = 43;
			var progressActivity = $"Scanning registry for DPAPI blobs on {serverName}";

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var key = OpenRegistryKey(session.Client, parsed, access, cancellationToken);
				ScanRegistryKey(smb, serverName, key, parsed.KeyPath, progressId, progressActivity, cancellationToken);
			});

			this.WriteProgress(new ProgressRecord(progressId, progressActivity, "Completed")
			{
				RecordType = ProgressRecordType.Completed
			});
		}

		private void ScanFileSystemPath(
			ISmbProviderInfo smb,
			ISmbFileSystem fileSystem,
			UncPath path,
			int progressId,
			string progressActivity,
			CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();

			ISmbDirectory? dir = null;
			try
			{
				dir = fileSystem.OpenDirectory(path, cancellationToken);
				ScanDirectoryEntries(smb, fileSystem, dir, path, progressId, progressActivity, cancellationToken);
				return;
			}
			catch (NtstatusException ex) when (IsNotDirectory(ex))
			{
				// Fall through to file scan.
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				this.WriteWarning($"Find-TBODpapiBlobs could not open {path}: {ex.StatusCode}.");
				return;
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				this.WriteWarning($"Find-TBODpapiBlobs was denied access to {path}: {ex.StatusCode}.");
				return;
			}
			catch (Exception ex)
			{
				smb.LogException($"Find-TBODpapiBlobs failed to open {path}", ex);
				throw;
			}
			finally
			{
				if (dir != null)
					dir.Dispose();
			}

			ScanFile(smb, fileSystem, path, null, progressId, progressActivity, cancellationToken);
		}

		private void ScanDirectoryEntries(
			ISmbProviderInfo smb,
			ISmbFileSystem fileSystem,
			ISmbDirectory dir,
			UncPath directoryPath,
			int progressId,
			string progressActivity,
			CancellationToken cancellationToken)
		{
			this.WriteProgressUpdate(progressId, progressActivity, $"Scanning {directoryPath}");

			foreach (var entry in dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
			{
				cancellationToken.ThrowIfCancellationRequested();

				if (string.IsNullOrEmpty(entry.FileName))
					continue;
				if (entry.FileName is "." or "..")
					continue;

				var isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
				var isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
				if (isReparse && !this.FollowReparse.IsPresent)
					continue;

				var childPath = directoryPath.Append(entry.FileName);
				if (isDirectory)
				{
					if (!this.Recurse.IsPresent)
						continue;

					ScanFileSystemPath(smb, fileSystem, childPath, progressId, progressActivity, cancellationToken);
				}
				else
				{
					ScanFile(smb, fileSystem, childPath, entry.Size, progressId, progressActivity, cancellationToken);
				}
			}
		}

		private void ScanFile(
			ISmbProviderInfo smb,
			ISmbFileSystem fileSystem,
			UncPath filePath,
			ulong? fileSize,
			int progressId,
			string progressActivity,
			CancellationToken cancellationToken)
		{
			this.WriteProgressUpdate(progressId, progressActivity, $"Scanning {filePath}");

			byte[]? prefix = null;
			try
			{
				prefix = ReadFilePrefix(fileSystem, filePath, this.MaxBytes, cancellationToken);
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				return;
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				this.WriteWarning($"Find-TBODpapiBlobs was denied access to {filePath}: {ex.StatusCode}.");
				return;
			}
			catch (Exception ex)
			{
				smb.LogException($"Find-TBODpapiBlobs failed to read {filePath}", ex);
				this.WriteWarning($"Find-TBODpapiBlobs failed to read {filePath}: {ex.Message}");
				return;
			}

			if (prefix == null || prefix.Length == 0)
				return;

			var offset = DpapiHelpers.FindMagicOffset(prefix);
			if (offset < 0)
				return;

			this.WriteObject(new TboDpapiBlobInfo
			{
				ServerName = this.ServerName,
				Source = "File",
				Path = filePath.ToString(),
				FileSize = fileSize.HasValue ? (long)fileSize.Value : null,
				MatchOffset = offset,
				BytesScanned = prefix.Length
			});
		}

		private void ScanRegistryKey(
			ISmbProviderInfo smb,
			string serverName,
			IRegistryKey key,
			string keyPath,
			int progressId,
			string progressActivity,
			CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();
			this.WriteProgressUpdate(progressId, progressActivity, $"Scanning {keyPath}");

			List<RegistryValueInfo> values;
			try
			{
				values = CollectValues(key, includeData: true, cancellationToken);
			}
			catch (NotSupportedException ex)
			{
				smb.LogException($"Find-TBODpapiBlobs failed to enumerate values with data for {keyPath}", ex);
				values = CollectValues(key, includeData: false, cancellationToken);
				foreach (var valueInfo in values)
				{
					try
					{
						var fullInfo = key.GetValue(valueInfo.Name, cancellationToken).GetAwaiter().GetResult();
						ScanRegistryValue(serverName, keyPath, fullInfo);
					}
					catch (Exception valueEx)
					{
						smb.LogException($"Find-TBODpapiBlobs failed to read {keyPath}\\{valueInfo.Name}", valueEx);
						this.WriteWarning($"Find-TBODpapiBlobs failed to read {keyPath}\\{valueInfo.Name}: {valueEx.Message}");
					}
				}
				values = new List<RegistryValueInfo>();
			}
			catch (Exception ex)
			{
				smb.LogException($"Find-TBODpapiBlobs failed to enumerate values for {keyPath}", ex);
				this.WriteWarning($"Find-TBODpapiBlobs failed to enumerate values for {keyPath}: {ex.Message}");
				return;
			}

			foreach (var valueInfo in values)
			{
				ScanRegistryValue(serverName, keyPath, valueInfo);
			}

			if (!this.Recurse.IsPresent)
				return;

			List<RegistrySubkeyInfo> subkeys;
			try
			{
				subkeys = CollectSubkeys(key, cancellationToken);
			}
			catch (Exception ex)
			{
				smb.LogException($"Find-TBODpapiBlobs failed to enumerate subkeys for {keyPath}", ex);
				this.WriteWarning($"Find-TBODpapiBlobs failed to enumerate subkeys for {keyPath}: {ex.Message}");
				return;
			}

			foreach (var subkey in subkeys)
			{
				cancellationToken.ThrowIfCancellationRequested();

				var childPath = string.IsNullOrEmpty(keyPath) ? subkey.KeyName : $"{keyPath}\\{subkey.KeyName}";
				IRegistryKey? childKey = null;
				try
				{
					childKey = key.OpenSubkey(
						subkey.KeyName,
						RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys,
						RegistryKeyOptions.BackupRestore,
						cancellationToken).GetAwaiter().GetResult();
				}
				catch (Win32Exception ex) when (ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
				{
					this.WriteWarning($"Find-TBODpapiBlobs was denied access to {childPath}: {ex.Message}");
					continue;
				}
				catch (Exception ex)
				{
					smb.LogException($"Find-TBODpapiBlobs failed to open {childPath}", ex);
					this.WriteWarning($"Find-TBODpapiBlobs failed to open {childPath}: {ex.Message}");
					continue;
				}

				using (childKey)
				{
					ScanRegistryKey(smb, serverName, childKey, childPath, progressId, progressActivity, cancellationToken);
				}
			}
		}

		private void ScanRegistryValue(string serverName, string keyPath, RegistryValueInfo valueInfo)
		{
			if (valueInfo.Bytes == null || valueInfo.Bytes.Length == 0)
				return;

			var scanLength = Math.Min(this.MaxBytes, valueInfo.Bytes.Length);
			if (scanLength < DpapiHelpers.DpapiMagic.Length)
				return;

			var offset = DpapiHelpers.FindMagicOffset(valueInfo.Bytes.AsSpan(0, scanLength));
			if (offset < 0)
				return;

			var dataLength = valueInfo.DataLength > 0 ? valueInfo.DataLength : valueInfo.Bytes.Length;
			this.WriteObject(new TboDpapiBlobInfo
			{
				ServerName = serverName,
				Source = "Registry",
				Path = keyPath,
				ValueName = valueInfo.Name,
				ValueType = valueInfo.ValueType,
				DataLength = dataLength,
				MatchOffset = offset,
				BytesScanned = scanLength
			});
		}

		private static byte[] ReadFilePrefix(ISmbFileSystem fileSystem, UncPath path, int maxBytes, CancellationToken cancellationToken)
		{
			using var file = fileSystem.OpenFileRead(path, cancellationToken);
			using var stream = file.OpenRead();
			var buffer = new byte[maxBytes];
			var read = 0;
			while (read < buffer.Length)
			{
				var chunk = stream.Read(buffer, read, buffer.Length - read);
				if (chunk <= 0)
					break;
				read += chunk;
			}

			if (read == buffer.Length)
				return buffer;

			if (read <= 0)
				return Array.Empty<byte>();

			Array.Resize(ref buffer, read);
			return buffer;
		}

		private void WriteProgressUpdate(int progressId, string activity, string status)
		{
			var record = new ProgressRecord(progressId, activity, status)
			{
				RecordType = ProgressRecordType.Processing
			};
			// Cmdlets may be called from non-interactive hosts; WriteProgress handles that gracefully.
			this.WriteProgress(record);
		}

		private static bool IsMissingPath(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_NAME_INVALID;
		}

		private static bool IsAccessDenied(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_ACCESS_DENIED
				or Ntstatus.STATUS_PRIVILEGE_NOT_HELD;
		}

		private static bool IsNotDirectory(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_NOT_A_DIRECTORY
				or Ntstatus.STATUS_FILE_IS_A_DIRECTORY;
		}

		private UncPath ResolveToUncPath(string path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", paramName);

			if (UncPath.TryParse(path, out var uncPath) && uncPath != null)
				return uncPath;

			ProviderInfo? providerInfo;
			PSDriveInfo? driveInfo;
			string providerPath;
			try
			{
				providerPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out providerInfo, out driveInfo);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"Path could not be resolved: {path}", paramName, ex);
			}

			if (providerInfo == null || !providerInfo.Name.Equals(SmbProvider.ProviderName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Path must be a UNC path or a {SmbProvider.ProviderName} PSDrive path: {path}", paramName);

			if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
				return resolvedUnc;

			throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
		}
	}
}
