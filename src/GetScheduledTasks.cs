using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
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
	public sealed class TboScheduledTaskInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string TaskName { get; init; } = string.Empty;
		public string TaskPath { get; init; } = string.Empty;
		public string TaskFilePath { get; init; } = string.Empty;
		public string? TaskId { get; init; }
		public DateTime? FileCreationTime { get; init; }
		public DateTime? FileLastWriteTime { get; init; }
		public DateTime? FileLastChangeTime { get; init; }
		public DateTime? RegistryLastWriteTime { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBOScheduledTasks")]
	[OutputType(typeof(TboScheduledTaskInfo))]
	public sealed class GetTBOScheduledTasks : TboRegCmdlet
	{
		private const string TaskCacheTreePath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
		private const string TasksFolderPath = @"Windows\System32\Tasks";
		private const RegistryKeyOptions BackupOptions = RegistryKeyOptions.BackupRestore;

		[Parameter(Position = 1)]
		[Alias("TaskName")]
		public string[]? Name { get; set; }

		[Parameter(Position = 2)]
		[Alias("TaskPath")]
		public string[]? Path { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			Dictionary<string, TaskCacheEntry> taskCache;
			try
			{
				taskCache = ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					return CollectTaskCacheEntries(session.Client, cancellationToken);
				});
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				smb.LogException($"Get-TBOScheduledTasks failed to read TaskCache registry for {this.ServerName}", ex);
				this.WriteWarning("Get-TBOScheduledTasks could not read TaskCache registry data (STATUS_PIPE_BUSY). TaskId and RegistryLastWriteTime will be blank.");
				taskCache = new Dictionary<string, TaskCacheEntry>(StringComparer.OrdinalIgnoreCase);
			}

			List<TaskFileEntry> taskFiles;
			try
			{
				taskFiles = EnumerateTaskFiles(smb, cancellationToken);
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBOScheduledTasks failed to enumerate task files on {this.ServerName}", ex);
				throw;
			}

			var nameFilters = BuildFilters(this.Name, normalizePath: false);
			var pathFilters = BuildFilters(this.Path, normalizePath: true);
			var emitted = 0;

			foreach (var taskFile in taskFiles)
			{
				var relativePath = taskFile.RelativePath;
				var taskName = GetTaskName(relativePath);
				var taskPath = NormalizeTaskPath(relativePath);

				if (!MatchesFilters(nameFilters, taskName))
					continue;
				if (!MatchesFilters(pathFilters, NormalizeRelativePath(relativePath)))
					continue;

				taskCache.TryGetValue(NormalizeRelativePath(relativePath), out var cacheEntry);

				emitted++;
				this.WriteObject(new TboScheduledTaskInfo
				{
					ServerName = this.ServerName,
					TaskName = taskName,
					TaskPath = taskPath,
					TaskFilePath = taskFile.UncPath.ToString(),
					TaskId = cacheEntry?.TaskId,
					FileCreationTime = taskFile.CreationTime,
					FileLastWriteTime = taskFile.LastWriteTime,
					FileLastChangeTime = taskFile.LastChangeTime,
					RegistryLastWriteTime = cacheEntry?.RegistryLastWriteTime
				});
			}

			if (emitted == 0 && (nameFilters.Count > 0 || pathFilters.Count > 0))
				this.WriteWarning("Get-TBOScheduledTasks did not match any tasks for the provided filters.");
		}

		private sealed class TaskFileEntry
		{
			public string RelativePath { get; init; } = string.Empty;
			public UncPath UncPath { get; init; } = null!;
			public DateTime CreationTime { get; init; }
			public DateTime LastWriteTime { get; init; }
			public DateTime LastChangeTime { get; init; }
		}

		private sealed class TaskCacheEntry
		{
			public string TaskId { get; init; } = string.Empty;
			public DateTime? RegistryLastWriteTime { get; init; }
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

		private Dictionary<string, TaskCacheEntry> CollectTaskCacheEntries(RemoteRegistryClient client, CancellationToken cancellationToken)
		{
			var spec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				TaskCacheTreePath);

			using var treeKey = OpenRegistryKey(client, spec, RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue, cancellationToken);
			var entries = new Dictionary<string, TaskCacheEntry>(StringComparer.OrdinalIgnoreCase);
			CollectTaskCacheEntries(treeKey, string.Empty, entries, cancellationToken);
			return entries;
		}

		private void CollectTaskCacheEntries(
			RegistryKey parentKey,
			string relativePath,
			Dictionary<string, TaskCacheEntry> entries,
			CancellationToken cancellationToken)
		{
			var subkeys = CollectSubkeys(parentKey, cancellationToken);
			foreach (var subkeyInfo in subkeys)
			{
				var name = subkeyInfo.KeyName;
				if (string.IsNullOrWhiteSpace(name))
					continue;

				var childRelative = CombineRelativePath(relativePath, name);
				RegistryKey? subkey = null;
				try
				{
					subkey = parentKey.OpenSubkey(
						name,
						RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
						BackupOptions,
						cancellationToken).GetAwaiter().GetResult();
				}
				catch (Win32Exception ex) when (IsMissingKey(ex) || ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
				{
					continue;
				}

				using (subkey)
				{

					var taskId = TryReadTaskId(subkey, cancellationToken);
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
							RegistryLastWriteTime = lastWrite
						};
					}

					CollectTaskCacheEntries(subkey, childRelative, entries, cancellationToken);
				}
			}
		}

		private static string? TryReadTaskId(RegistryKey key, CancellationToken cancellationToken)
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

		private static List<WildcardPattern> BuildFilters(string[]? filters, bool normalizePath)
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

		private static bool MatchesFilters(List<WildcardPattern> filters, string value)
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

		private static string NormalizeRelativePath(string path)
		{
			var normalized = path.Replace('/', '\\').Trim();
			if (normalized.StartsWith("\\", StringComparison.Ordinal))
				normalized = normalized.TrimStart('\\');
			return normalized;
		}

		private static string NormalizeTaskPath(string relativePath)
		{
			var normalized = NormalizeRelativePath(relativePath);
			return "\\" + normalized;
		}

		private static string CombineRelativePath(string basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}

		private static string GetTaskName(string relativePath)
		{
			if (string.IsNullOrWhiteSpace(relativePath))
				return string.Empty;

			var normalized = NormalizeRelativePath(relativePath);
			var index = normalized.LastIndexOf('\\');
			if (index >= 0 && index < normalized.Length - 1)
				return normalized.Substring(index + 1);
			return normalized;
		}

		private static bool IsMissingKey(Win32Exception ex)
		{
			return ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME;
		}
	}
}
