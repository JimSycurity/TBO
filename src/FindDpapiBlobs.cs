using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
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

		public string? CredentialGuid { get; init; }
		public string? MasterKeyGuid { get; init; }
		public uint? Flags { get; init; }
		public string? Description { get; init; }
		public uint? CryptAlgorithmId { get; init; }
		public string? CryptAlgorithm { get; init; }
		public uint? HashAlgorithmId { get; init; }
		public string? HashAlgorithm { get; init; }
		public string? ParseFailureReason { get; init; }
	}

	[Cmdlet(VerbsCommon.Find, "TBODpapiBlobs", DefaultParameterSetName = FileSystemParameterSet)]
	[OutputType(typeof(TboDpapiBlobInfo))]
	public sealed class FindTBODpapiBlobs : TboRegCmdlet
	{
		private const string FileSystemParameterSet = "FileSystem";
		private const string RegistryParameterSet = "Registry";
		private const int DefaultMaxBytes = 1024;
		private const int PipeBusyRetryCount = 6;
		private const int PipeBusyInitialDelayMs = 200;
		private const int PipeBusyMaxDelayMs = 2000;
		private const int PipeBusyRetryLogIntervalMs = 5000;

		private TboCacheDatabase? _cacheDb;
		private long _cacheMachineId;
		private int _pipeBusyAdaptiveDelayMs;
		private int _pipeBusySuppressedLogCount;
		private DateTime _pipeBusyNextVerboseUtc;

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

			var ingestCache = this.ResolveCacheIngestionEnabled(this.Cache);
			try
			{
				if (ingestCache)
				{
					try
					{
						_cacheDb = TboCacheDatabase.Open(this.CachePath, msg => this.WriteVerbose(msg));
						_cacheMachineId = _cacheDb.UpsertMachine(serverName);
					}
					catch (Exception ex)
					{
						_cacheDb?.Dispose();
						_cacheDb = null;
						_cacheMachineId = 0;
						this.LogException(smb, $"Find-TBODpapiBlobs failed to open cache DB for {serverName}", ex, emitWarning: false);
						this.LogWarning(smb, $"Find-TBODpapiBlobs cache write disabled: {ex.Message}");
					}
				}

				if (this.ParameterSetName == RegistryParameterSet)
				{
					FindRegistryBlobs(smb, serverName, cancellationToken);
					return;
				}

				FindFileSystemBlobs(smb, serverName, cancellationToken);
			}
			finally
			{
				FlushSuppressedPipeBusyLogs(smb);
				_cacheDb?.Dispose();
				_cacheDb = null;
				_cacheMachineId = 0;
			}
		}

		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

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
			catch (NtstatusException ex) when (IsFileBusy(ex))
			{
				this.LogVerbose(smb, $"Find-TBODpapiBlobs skipped locked file {filePath}: {ex.StatusCode}.");
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

			WriteBlobHit(
				smb,
				serverName: this.ServerName,
				source: "File",
				path: filePath.ToString(),
				valueName: null,
				valueType: null,
				dataLength: null,
				fileSize: fileSize.HasValue ? (long)fileSize.Value : null,
				matchOffset: offset,
				bytesScanned: prefix.Length,
				buffer: prefix);
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
				values = ExecutePipeBusyRetry(
					smb,
					operationName: $"enumerating values for {keyPath}",
					cancellationToken,
					() => CollectValues(key, includeData: true, cancellationToken));
			}
			catch (NotSupportedException ex)
			{
				smb.LogException($"Find-TBODpapiBlobs failed to enumerate values with data for {keyPath}", ex);
				values = ExecutePipeBusyRetry(
					smb,
					operationName: $"enumerating values for {keyPath} (metadata mode)",
					cancellationToken,
					() => CollectValues(key, includeData: false, cancellationToken));
				foreach (var valueInfo in values)
				{
					try
					{
						var fullInfo = ExecutePipeBusyRetry(
							smb,
							operationName: $"reading value {keyPath}\\{valueInfo.Name}",
							cancellationToken,
							() => key.GetValue(valueInfo.Name, cancellationToken).GetAwaiter().GetResult());
						ScanRegistryValue(smb, serverName, keyPath, fullInfo);
					}
					catch (Win32Exception valueEx) when (valueEx.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
					{
						this.LogVerbose(smb, $"Find-TBODpapiBlobs skipped value {keyPath}\\{valueInfo.Name}: {valueEx.Message}");
					}
					catch (Exception valueEx)
					{
						smb.LogException($"Find-TBODpapiBlobs failed to read {keyPath}\\{valueInfo.Name}", valueEx);
						this.WriteWarning($"Find-TBODpapiBlobs failed to read {keyPath}\\{valueInfo.Name}: {valueEx.Message}");
					}
				}
				values = new List<RegistryValueInfo>();
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
			{
				this.LogVerbose(smb, $"Find-TBODpapiBlobs skipped value enumeration for {keyPath}: {ex.Message}");
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
				ScanRegistryValue(smb, serverName, keyPath, valueInfo);
			}

			if (!this.Recurse.IsPresent)
				return;

			List<RegistrySubkeyInfo> subkeys;
			try
			{
				subkeys = ExecutePipeBusyRetry(
					smb,
					operationName: $"enumerating subkeys for {keyPath}",
					cancellationToken,
					() => CollectSubkeys(key, cancellationToken));
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
			{
				this.LogVerbose(smb, $"Find-TBODpapiBlobs skipped subkey enumeration for {keyPath}: {ex.Message}");
				return;
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
					childKey = ExecutePipeBusyRetry(
						smb,
						operationName: $"opening subkey {childPath}",
						cancellationToken,
						() => key.OpenSubkey(
							subkey.KeyName,
							RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys,
							RegistryKeyOptions.BackupRestore,
							cancellationToken).GetAwaiter().GetResult());
				}
				catch (Win32Exception ex) when (ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
				{
					this.LogVerbose(smb, $"Find-TBODpapiBlobs skipped subkey {childPath}: {ex.Message}");
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

		private void ScanRegistryValue(ISmbProviderInfo smb, string serverName, string keyPath, RegistryValueInfo valueInfo)
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
			WriteBlobHit(
				smb,
				serverName: serverName,
				source: "Registry",
				path: keyPath,
				valueName: valueInfo.Name,
				valueType: valueInfo.ValueType,
				dataLength: dataLength,
				fileSize: null,
				matchOffset: offset,
				bytesScanned: scanLength,
				buffer: valueInfo.Bytes);
		}

		private void WriteBlobHit(
			ISmbProviderInfo smb,
			string serverName,
			string source,
			string path,
			string? valueName,
			RegistryValueType? valueType,
			int? dataLength,
			long? fileSize,
			int matchOffset,
			int bytesScanned,
			ReadOnlySpan<byte> buffer)
		{
			string? credentialGuid = null;
			string? masterKeyGuid = null;
			uint? flags = null;
			string? description = null;
			uint? cryptAlgorithmId = null;
			string? cryptAlgorithm = null;
			uint? hashAlgorithmId = null;
			string? hashAlgorithm = null;
			string? parseFailureReason = null;

			if (DpapiBlobCrypto.TryParseHeader(buffer, matchOffset, out var header, out var headerFailure))
			{
				credentialGuid = header.GuidCredential.ToString();
				masterKeyGuid = header.GuidMasterKey.ToString();
				flags = header.Flags;
				description = header.Description;

				if (header.CryptAlgorithm.HasValue && header.CryptAlgorithmLength.HasValue)
				{
					cryptAlgorithmId = header.CryptAlgorithm.Value;
					cryptAlgorithm = DpapiBlobCrypto.ResolveCipherAlgorithmName(header.CryptAlgorithm.Value, header.CryptAlgorithmLength.Value);
				}

				if (header.HashAlgorithm.HasValue && header.HashAlgorithmLength.HasValue)
				{
					hashAlgorithmId = header.HashAlgorithm.Value;
					hashAlgorithm = DpapiBlobCrypto.ResolveHashAlgorithmName(header.HashAlgorithm.Value, header.HashAlgorithmLength.Value);
				}

				parseFailureReason = headerFailure;
			}
			else
			{
				parseFailureReason = headerFailure;
			}

			var info = new TboDpapiBlobInfo
			{
				ServerName = serverName,
				Source = source,
				Path = path,
				ValueName = valueName,
				ValueType = valueType,
				DataLength = dataLength,
				FileSize = fileSize,
				MatchOffset = matchOffset,
				BytesScanned = bytesScanned,

				CredentialGuid = credentialGuid,
				MasterKeyGuid = masterKeyGuid,
				Flags = flags,
				Description = description,
				CryptAlgorithmId = cryptAlgorithmId,
				CryptAlgorithm = cryptAlgorithm,
				HashAlgorithmId = hashAlgorithmId,
				HashAlgorithm = hashAlgorithm,
				ParseFailureReason = parseFailureReason
			};

			if (_cacheDb != null && _cacheMachineId > 0)
			{
				var blobKey = BuildBlobKey(source, path, valueName, matchOffset);
				try
				{
					var valueTypeInt = valueType.HasValue ? (int)valueType.Value : (int?)null;
					_cacheDb.UpsertDpapiBlob(
						machineId: _cacheMachineId,
						blobKey: blobKey,
						source: source,
						path: path,
						valueName: valueName,
						valueType: valueTypeInt,
						dataLength: dataLength,
						fileSize: fileSize,
						matchOffset: matchOffset,
						bytesScanned: bytesScanned,
						credentialGuid: credentialGuid,
						masterKeyGuid: masterKeyGuid,
						flags: flags,
						description: description,
						cryptAlgorithmId: cryptAlgorithmId,
						hashAlgorithmId: hashAlgorithmId,
						parseFailureReason: parseFailureReason);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Find-TBODpapiBlobs failed to write cache blob record for {serverName}", ex, emitWarning: false);
					this.LogWarning(smb, $"Find-TBODpapiBlobs cache write failed: {ex.Message}");
				}
			}

			this.WriteObject(info);
		}

		private static string BuildBlobKey(string source, string path, string? valueName, int matchOffset)
		{
			var safeSource = source?.Trim() ?? string.Empty;
			var safePath = path?.Trim() ?? string.Empty;
			var safeValueName = valueName?.Trim() ?? string.Empty;

			if (safeSource.Equals("Registry", StringComparison.OrdinalIgnoreCase))
				return $"Registry|{safePath}|{safeValueName}|{matchOffset}";

			return $"{safeSource}|{safePath}|{matchOffset}";
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

		private static bool IsFileBusy(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_SHARING_VIOLATION
				or Ntstatus.STATUS_FILE_LOCK_CONFLICT
				or Ntstatus.STATUS_LOCK_NOT_GRANTED
				or Ntstatus.STATUS_DELETE_PENDING;
		}

		private T ExecutePipeBusyRetry<T>(
			ISmbProviderInfo smb,
			string operationName,
			CancellationToken cancellationToken,
			Func<T> action)
		{
			if (action == null)
				throw new ArgumentNullException(nameof(action));

			if (_pipeBusyAdaptiveDelayMs > 0)
			{
				Task.Delay(_pipeBusyAdaptiveDelayMs, cancellationToken).GetAwaiter().GetResult();
			}

			var delayMs = PipeBusyInitialDelayMs;
			for (var attempt = 1; ; attempt++)
			{
				cancellationToken.ThrowIfCancellationRequested();
				try
				{
					var result = action();
					if (_pipeBusyAdaptiveDelayMs > 0)
						_pipeBusyAdaptiveDelayMs = Math.Max(0, _pipeBusyAdaptiveDelayMs - 25);
					return result;
				}
				catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY && attempt <= PipeBusyRetryCount)
				{
					_pipeBusyAdaptiveDelayMs = Math.Min(PipeBusyMaxDelayMs, Math.Max(_pipeBusyAdaptiveDelayMs, delayMs));
					LogPipeBusyRetry(smb, operationName, attempt, delayMs);
					Task.Delay(delayMs, cancellationToken).GetAwaiter().GetResult();
					delayMs = Math.Min(delayMs * 2, PipeBusyMaxDelayMs);
				}
			}
		}

		private void LogPipeBusyRetry(ISmbProviderInfo smb, string operationName, int attempt, int delayMs)
		{
			var nowUtc = DateTime.UtcNow;
			if (nowUtc >= _pipeBusyNextVerboseUtc)
			{
				FlushSuppressedPipeBusyLogs(smb);
				this.LogVerbose(smb,
					$"Find-TBODpapiBlobs throttling after STATUS_PIPE_BUSY while {operationName} (retry {attempt}/{PipeBusyRetryCount}, delay {delayMs}ms).");
				_pipeBusyNextVerboseUtc = nowUtc.AddMilliseconds(PipeBusyRetryLogIntervalMs);
				return;
			}

			_pipeBusySuppressedLogCount++;
		}

		private void FlushSuppressedPipeBusyLogs(ISmbProviderInfo smb)
		{
			if (_pipeBusySuppressedLogCount <= 0)
				return;

			this.LogVerbose(smb,
				$"Find-TBODpapiBlobs suppressed {_pipeBusySuppressedLogCount} additional STATUS_PIPE_BUSY retry log entr{(_pipeBusySuppressedLogCount == 1 ? "y" : "ies")}.");
			_pipeBusySuppressedLogCount = 0;
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
