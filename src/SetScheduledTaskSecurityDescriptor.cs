using System;
using System.ComponentModel;
using System.Management.Automation;
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

					key.SetValue("SD", RegistryValueType.Binary, securityDescriptorBytes, cancellationToken).GetAwaiter().GetResult();
				});
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				throw new InvalidOperationException($"Failed to set scheduled task security descriptor for '{taskPath}' (STATUS_PIPE_BUSY). Retry the operation.", ex);
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				|| ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				|| ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_BAD_PATHNAME)
			{
				throw new ArgumentException($"Scheduled task registry key not found for task path '{taskPath}'.", nameof(taskPath), ex);
			}
		}
	}
}
