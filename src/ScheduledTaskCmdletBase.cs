using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Management.Automation;
using System.Text;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class TaskFileEntry
	{
		public string RelativePath { get; init; } = string.Empty;
		public UncPath UncPath { get; init; } = null!;
		public DateTime CreationTime { get; init; }
		public DateTime LastWriteTime { get; init; }
		public DateTime LastChangeTime { get; init; }
	}

	internal sealed class TaskCacheEntry
	{
		public string TaskId { get; init; } = string.Empty;
		public DateTime? RegistryLastWriteTime { get; init; }
		public byte[]? TaskSecurityDescriptorBytes { get; init; }
	}

	public abstract class ScheduledTaskCmdletBase : TboRegCmdlet
	{
		protected const string TaskCacheTreePath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
		protected const string TasksFolderPath = @"Windows\System32\Tasks";
		protected const RegistryKeyOptions BackupOptions = RegistryKeyOptions.BackupRestore;

		internal Dictionary<string, TaskCacheEntry> ReadTaskCacheEntries(
			ISmbProviderInfo smb,
			CancellationToken cancellationToken,
			string contextLabel,
			out int pipeBusyCount)
		{
			pipeBusyCount = 0;
			try
			{
				var result = ExecuteRegistryOperation(smb, cancellationToken, session =>
					CollectTaskCacheEntries(session.Client, cancellationToken));
				pipeBusyCount = result.pipeBusyCount;
				return result.entries;
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				this.LogException(smb, $"{contextLabel} failed to read TaskCache registry for {this.ServerName}", ex);
				this.LogWarning(smb, $"{contextLabel} could not read TaskCache registry data (STATUS_PIPE_BUSY). TaskId and RegistryLastWriteTime will be blank.");
				return new Dictionary<string, TaskCacheEntry>(StringComparer.OrdinalIgnoreCase);
			}
		}

		internal List<TaskFileEntry> ReadTaskFiles(ISmbProviderInfo smb, CancellationToken cancellationToken, string contextLabel)
		{
			try
			{
				return EnumerateTaskFiles(smb, cancellationToken);
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"{contextLabel} failed to enumerate task files on {this.ServerName}", ex);
				throw;
			}
		}

		protected static List<WildcardPattern> BuildFilters(string[]? filters, bool normalizePath)
		{
			var patterns = new List<WildcardPattern>();
			if (filters == null)
				return patterns;

			foreach (var filter in filters)
			{
				if (string.IsNullOrWhiteSpace(filter))
					continue;

				var normalized = normalizePath ? NormalizeRelativePath(filter) : filter.Trim();
				if (string.IsNullOrWhiteSpace(normalized))
					continue;

				patterns.Add(new WildcardPattern(normalized, WildcardOptions.IgnoreCase));
			}

			return patterns;
		}

		protected static bool MatchesFilters(List<WildcardPattern> filters, string value)
		{
			if (filters.Count == 0)
				return true;

			foreach (var filter in filters)
			{
				if (filter.IsMatch(value))
					return true;
			}

			return false;
		}

		protected static string NormalizeRelativePath(string path)
		{
			var normalized = path.Replace('/', '\\').Trim();
			if (normalized.StartsWith("\\", StringComparison.Ordinal))
				normalized = normalized.TrimStart('\\');
			return normalized;
		}

		protected static string NormalizeTaskPath(string relativePath)
		{
			var normalized = NormalizeRelativePath(relativePath);
			return "\\" + normalized;
		}

		protected static string CombineRelativePath(string basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}

		protected static string GetTaskName(string relativePath)
		{
			if (string.IsNullOrWhiteSpace(relativePath))
				return string.Empty;

			var normalized = NormalizeRelativePath(relativePath);
			var index = normalized.LastIndexOf('\\');
			if (index >= 0 && index < normalized.Length - 1)
				return normalized.Substring(index + 1);
			return normalized;
		}

		protected static bool IsMissingKey(Win32Exception ex)
		{
			return ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME;
		}

		private List<TaskFileEntry> EnumerateTaskFiles(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var uncRoot = UncPath.Parse($"\\\\{this.ServerName}\\C$\\{TasksFolderPath}");
			var results = new List<TaskFileEntry>();
			EnumerateTaskFiles(smb.SmbClient, uncRoot, string.Empty, results, cancellationToken);
			return results;
		}

		private void EnumerateTaskFiles(
			Smb2Client client,
			UncPath directoryPath,
			string relativePath,
			List<TaskFileEntry> results,
			CancellationToken cancellationToken)
		{
			using var dir = OpenDirectory(client, directoryPath, cancellationToken);

			foreach (var entry in dir.QueryDirAsync("*", Smb2Directory.Smb2DirQueryOptions.QueryReparseInfo, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken).GetAwaiter().GetResult())
			{
				if (string.IsNullOrEmpty(entry.FileName))
					continue;
				if (entry.FileName is "." or "..")
					continue;

				bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
				bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
				var childRelative = CombineRelativePath(relativePath, entry.FileName);
				var childPath = directoryPath.Append(entry.FileName);

				if (isDirectory)
				{
					if (isReparse)
						continue;

					EnumerateTaskFiles(client, childPath, childRelative, results, cancellationToken);
					continue;
				}

				results.Add(new TaskFileEntry
				{
					RelativePath = childRelative,
					UncPath = childPath,
					CreationTime = entry.CreationTime,
					LastWriteTime = entry.LastWriteTime,
					LastChangeTime = entry.LastChangeTime
				});
			}
		}

		private static Smb2Directory OpenDirectory(Smb2Client client, UncPath path, CancellationToken cancellationToken)
		{
			return (Smb2Directory)client.CreateFileAsync(path, new Smb2CreateInfo
			{
				CreateDisposition = Smb2CreateDisposition.Open,
				Priority = Smb2Priority.OpenDir,
				DesiredAccess = (uint)Smb2AccessRights.DefaultOpenDirAccess,
				ShareAccess = Smb2ShareAccess.DefaultDirShare,
				FileAttributes = Winterop.FileAttributes.None,
				CreateOptions = Smb2FileCreateOptions.Directory
					| Smb2FileCreateOptions.SynchronousIoNonalert
					| Smb2FileCreateOptions.OpenForBackupIntent,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				RequestMaximalAccess = true,
				QueryOnDiskId = true,
				OplockLevel = Smb2OplockLevel.None
			}, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();
		}

		private (Dictionary<string, TaskCacheEntry> entries, int pipeBusyCount) CollectTaskCacheEntries(IRegistryClient client, CancellationToken cancellationToken)
		{
			var pipeBusyCount = 0;
			var spec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				TaskCacheTreePath);

			using var treeKey = OpenRegistryKey(client, spec, RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue, cancellationToken);
			var entries = new Dictionary<string, TaskCacheEntry>(StringComparer.OrdinalIgnoreCase);
			CollectTaskCacheEntries(treeKey, string.Empty, entries, cancellationToken, ref pipeBusyCount);
			return (entries, pipeBusyCount);
		}

		private void CollectTaskCacheEntries(
			IRegistryKey parentKey,
			string relativePath,
			Dictionary<string, TaskCacheEntry> entries,
			CancellationToken cancellationToken,
			ref int pipeBusyCount)
		{
			var subkeys = CollectSubkeys(parentKey, cancellationToken);
			foreach (var subkeyInfo in subkeys)
			{
				var name = subkeyInfo.KeyName;
				if (string.IsNullOrWhiteSpace(name))
					continue;

				var childRelative = CombineRelativePath(relativePath, name);
				IRegistryKey? subkey = null;
				try
				{
					subkey = parentKey.OpenSubkey(
						name,
						RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
						BackupOptions,
						cancellationToken).GetAwaiter().GetResult();
				}
				catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
				{
					pipeBusyCount++;
					continue;
				}
				catch (Win32Exception ex) when (IsMissingKey(ex) || ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
				{
					continue;
				}

				using (subkey)
				{
					var taskId = TryReadTaskId(subkey, cancellationToken);
					var taskSdBytes = TryReadTaskSecurityDescriptorBytes(subkey, cancellationToken);
					DateTime? lastWrite = null;
					try
					{
						lastWrite = subkey.QueryInfo(cancellationToken).GetAwaiter().GetResult().LastWriteTime;
					}
					catch
					{
					}

					if (!string.IsNullOrWhiteSpace(taskId))
					{
						entries[NormalizeRelativePath(childRelative)] = new TaskCacheEntry
						{
							TaskId = taskId,
							RegistryLastWriteTime = lastWrite,
							TaskSecurityDescriptorBytes = taskSdBytes
						};
					}

					CollectTaskCacheEntries(subkey, childRelative, entries, cancellationToken, ref pipeBusyCount);
				}
			}
		}

		private static byte[]? TryReadTaskSecurityDescriptorBytes(IRegistryKey key, CancellationToken cancellationToken)
		{
			try
			{
				// TaskCache leaf keys store the task's security descriptor as a REG_BINARY value named "SD".
				// The value is a binary (self-relative) security descriptor (same bytes used by Win32_SecurityDescriptorHelper).
				var valueInfo = key.GetValue("SD", cancellationToken).GetAwaiter().GetResult();
				return RegistryHelpers.ExtractValueBytes(valueInfo);
			}
			catch (Win32Exception ex) when (IsMissingKey(ex) || ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
			{
				return null;
			}
			catch
			{
				return null;
			}
		}

		private static string? TryReadTaskId(IRegistryKey key, CancellationToken cancellationToken)
		{
			try
			{
				var valueInfo = key.GetValue("Id", cancellationToken).GetAwaiter().GetResult();
				if (valueInfo.TypedValue is Guid guid)
					return guid.ToString();
				if (valueInfo.TypedValue is string str && Guid.TryParse(str, out var parsed))
					return parsed.ToString();
				if (valueInfo.TypedValue is byte[] bytes && bytes.Length >= 16)
				{
					var asGuid = TryParseGuidFromBytes(bytes);
					if (asGuid != null)
						return asGuid;
				}
				if (valueInfo.Bytes != null && valueInfo.Bytes.Length > 0)
				{
					var asGuid = TryParseGuidFromBytes(valueInfo.Bytes);
					if (asGuid != null)
						return asGuid;
				}
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return null;
			}

			return null;
		}

		private static string? TryParseGuidFromBytes(byte[] bytes)
		{
			if (bytes.Length == 16)
				return new Guid(bytes).ToString();

			var text = Encoding.Unicode.GetString(bytes).TrimEnd('\0');
			if (Guid.TryParse(text, out var parsed))
				return parsed.ToString();

			text = Encoding.UTF8.GetString(bytes).TrimEnd('\0');
			if (Guid.TryParse(text, out parsed))
				return parsed.ToString();

			return null;
		}
	}
}
