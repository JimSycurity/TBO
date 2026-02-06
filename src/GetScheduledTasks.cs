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
	public sealed class GetTBOScheduledTasks : ScheduledTaskCmdletBase
	{
		[Parameter(Position = 1)]
		[Alias("TaskName")]
		public string[]? Name { get; set; }

		[Parameter(Position = 2)]
		[Alias("TaskPath")]
		public string[]? Path { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var taskCache = ReadTaskCacheEntries(smb, cancellationToken, "Get-TBOScheduledTasks", out var pipeBusyCount);
			if (pipeBusyCount > 0)
			{
				this.LogWarning(smb, $"Get-TBOScheduledTasks skipped {pipeBusyCount} TaskCache subkey(s) due to STATUS_PIPE_BUSY. TaskId/RegistryLastWriteTime may be missing for some tasks.");
			}

			var taskFiles = ReadTaskFiles(smb, cancellationToken, "Get-TBOScheduledTasks");

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
				this.LogWarning(smb, "Get-TBOScheduledTasks did not match any tasks for the provided filters.");
		}
	}
}
