using System;
using System.ComponentModel;
using System.Management.Automation;
using System.Text.Json;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Set, "TBOScheduledTaskSecurityDescriptor", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class SetTBOScheduledTaskSecurityDescriptor : ScheduledTaskCmdletBase
	{
		private const string InputObjectParameterSet = "InputObject";
		private const string PathParameterSet = "Path";

		[Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = InputObjectParameterSet)]
		public TboScheduledTaskDetailsInfo? InputObject { get; set; }

		[Parameter(Mandatory = true, Position = 1, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet)]
		[Alias("TaskPath")]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 2)]
		public object SecurityDescriptor { get; set; } = null!;

		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			// TaskCache SD values are stored as raw binary security descriptor bytes.
			// Accept byte[] inputs verbatim so users can round-trip the value even if the portable SD parser cannot.
			var securityDescriptorBytes = SecurityDescriptorInputHelpers.ResolveBinarySecurityDescriptorBytes(this.SecurityDescriptor);

			if (this.ParameterSetName == InputObjectParameterSet)
			{
				if (this.InputObject == null)
					return;

				SetTaskSecurityDescriptorValue(smb, this.InputObject.TaskPath, securityDescriptorBytes, cancellationToken);
				return;
			}

			SetTaskSecurityDescriptorValue(smb, this.Path, securityDescriptorBytes, cancellationToken);
		}

		private void SetTaskSecurityDescriptorValue(ISmbProviderInfo smb, string taskPath, byte[] securityDescriptorBytes, CancellationToken cancellationToken)
		{
			var recordActivity = this.ResolveCacheIngestionEnabled(this.Cache);

			if (string.IsNullOrWhiteSpace(taskPath))
				throw new ArgumentException("Task path must be provided.", nameof(taskPath));

			var relative = NormalizeRelativePath(taskPath);
			var subkeyPath = string.IsNullOrWhiteSpace(relative)
				? TaskCacheTreePath
				: $"{TaskCacheTreePath}\\{relative}";

			var spec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				subkeyPath);

			var target = $"{this.ServerName}:{spec.KeyPath}\\SD";
			if (!this.ShouldProcess(target, "Set scheduled task security descriptor"))
				return;

			byte[]? beforeBytes = null;
			string? beforeReadFailure = null;
			Exception? operationFailure = null;

			try
			{
				ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					using var key = OpenRegistryKey(
						session.Client,
						spec,
						RegistryAccessRights.SetValue | RegistryAccessRights.QueryValue,
						RegistryAccessRights.EnumerateSubkeys,
						cancellationToken);

					if (recordActivity)
					{
						try
						{
							var existing = key.GetValue("SD", cancellationToken).GetAwaiter().GetResult();
							if (existing.Bytes != null)
								beforeBytes = existing.Bytes;
							else if (existing.TypedValue != null)
								beforeBytes = RegistryHelpers.EncodeValue(existing.ValueType, existing.TypedValue);
							else
								beforeBytes = existing.Bytes;
						}
						catch (Exception ex)
						{
							beforeReadFailure = ex.Message;
							beforeBytes = null;
						}
					}

					key.SetValue("SD", RegistryValueType.Binary, securityDescriptorBytes, cancellationToken).GetAwaiter().GetResult();
				});
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				var wrapper = new InvalidOperationException($"Failed to set scheduled task security descriptor for '{taskPath}' (STATUS_PIPE_BUSY). Retry the operation.", ex);
				operationFailure = wrapper;
				throw wrapper;
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				|| ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				|| ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_BAD_PATHNAME)
			{
				var wrapper = new ArgumentException($"Scheduled task registry key not found for task path '{taskPath}'.", nameof(taskPath), ex);
				operationFailure = wrapper;
				throw wrapper;
			}
			catch (Exception ex)
			{
				operationFailure = ex;
				throw;
			}
			finally
			{
				string? contextJson = null;
				if (recordActivity)
				{
					contextJson = JsonSerializer.Serialize(new
					{
						taskPath,
						beforeReadFailure
					});
				}

				TboCacheWriteActivities.TryRecord(
					cmdlet: this,
					smb: smb,
					enabled: recordActivity,
					cachePath: this.CachePath,
					serverName: this.ServerName,
					kind: TboCacheWriteActivities.KindRegistry,
					action: TboCacheWriteActivities.ActionSetValue,
					target: target,
					path: spec.KeyPath,
					valueName: "SD",
					valueType: (int)RegistryValueType.Binary,
					beforeBlobKind: beforeBytes != null ? TboCacheWriteActivities.BlobKindRegistryValue : null,
					beforeBlob: beforeBytes,
					afterBlobKind: TboCacheWriteActivities.BlobKindRegistryValue,
					afterBlob: securityDescriptorBytes,
					contextJson: contextJson,
					success: operationFailure == null,
					failureReason: operationFailure?.Message);
			}
		}
	}
}
