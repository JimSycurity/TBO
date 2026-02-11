using System;
using System.Globalization;
using System.Management.Automation;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class TboCacheWriteActivities
	{
		internal const string KindRegistry = "Registry";
		internal const string KindFileSystem = "FileSystem";

		internal const string ActionCreateKey = "CreateKey";
		internal const string ActionDeleteKey = "DeleteKey";
		internal const string ActionSetValue = "SetValue";
		internal const string ActionDeleteValue = "DeleteValue";
		internal const string ActionSetSecurityDescriptor = "SetSecurityDescriptor";
		internal const string ActionWriteFile = "WriteFile";
		internal const string ActionCopyItem = "CopyItem";

		internal const string BlobKindRegistryValue = "RegistryValue";
		internal const string BlobKindSecurityDescriptor = "SecurityDescriptor";

		internal static void TryRecord(
			PSCmdlet cmdlet,
			ISmbProviderInfo smb,
			bool enabled,
			string? cachePath,
			string serverName,
			string kind,
			string action,
			string target,
			string path,
			string? valueName,
			int? valueType,
			string? beforeBlobKind,
			byte[]? beforeBlob,
			string? afterBlobKind,
			byte[]? afterBlob,
			string? contextJson,
			bool success,
			string? failureReason,
			DateTime? activityUtc = null)
		{
			if (!enabled)
				return;

			ArgumentNullException.ThrowIfNull(cmdlet);
			ArgumentNullException.ThrowIfNull(smb);

			var cmdletName = cmdlet.MyInvocation?.MyCommand?.Name;
			if (string.IsNullOrWhiteSpace(cmdletName))
				cmdletName = "UnknownCmdlet";

			try
			{
				using var db = TboCacheDatabase.Open(cachePath, msg => cmdlet.WriteVerbose(msg));
				var machineId = db.UpsertMachine(serverName);
				db.InsertWriteActivity(
					machineId,
					cmdletName,
					kind,
					action,
					target,
					path,
					valueName,
					valueType,
					beforeBlobKind,
					beforeBlob,
					afterBlobKind,
					afterBlob,
					contextJson,
					success,
					failureReason,
					activityUtc);
			}
			catch (Exception ex)
			{
				smb.LogException($"{cmdletName} failed to write cache activity for {serverName}", ex);
				cmdlet.WriteWarning(string.Format(
					CultureInfo.InvariantCulture,
					"{0} cache write activity failed: {1}",
					cmdletName,
					ex.Message));
			}
		}
	}
}
