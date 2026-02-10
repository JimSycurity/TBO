using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Text.Json;
using System.Threading;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboEnvironmentVariableInfo
	{
		public TboEnvironmentVariableInfo(
			string serverName,
			string scope,
			string? userSid,
			string keyPath,
			RegistryValueInfo info)
		{
			this.ServerName = serverName;
			this.Scope = scope;
			this.UserSid = userSid;
			this.KeyPath = keyPath;

			this.Name = info.Name;
			this.ValueType = info.ValueType;
			this.DataLength = info.DataLength;
			this.Bytes = info.Bytes;
			this.Value = info.TypedValue;
		}

		public string ServerName { get; }
		public string Scope { get; }
		public string? UserSid { get; }
		public string KeyPath { get; }

		public string Name { get; }
		public RegistryValueType ValueType { get; }
		public int DataLength { get; }
		public byte[]? Bytes { get; }
		public object? Value { get; }
	}

	internal static class TboEnvironmentVariableRegistry
	{
		internal const string ScopeMachine = "Machine";
		internal const string ScopeUser = "User";

		internal const string MachineEnvironmentKey = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

		internal static RegistryPathSpec ResolvePathSpec(string scope, string? userSid, bool volatileUserKey)
		{
			if (string.Equals(scope, ScopeMachine, StringComparison.OrdinalIgnoreCase))
			{
				return RegistryPathParser.Parse(MachineEnvironmentKey, nameof(scope));
			}

			if (!string.Equals(scope, ScopeUser, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Unsupported scope '{scope}'.", nameof(scope));

			if (string.IsNullOrWhiteSpace(userSid))
				throw new ArgumentException("UserSid must be provided when Scope is User.", nameof(userSid));

			var leaf = volatileUserKey ? "Volatile Environment" : "Environment";
			var path = $@"HKU\{userSid}\{leaf}";
			return RegistryPathParser.Parse(path, nameof(userSid));
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOEnvironmentVariable")]
	[OutputType(typeof(TboEnvironmentVariableInfo))]
	public sealed class GetTBOEnvironmentVariable : TboRegCmdlet
	{
		[Parameter(Position = 1, ValueFromPipelineByPropertyName = true)]
		public string? Name { get; set; }

		[Parameter]
		[ValidateSet(TboEnvironmentVariableRegistry.ScopeMachine, TboEnvironmentVariableRegistry.ScopeUser)]
		public string Scope { get; set; } = TboEnvironmentVariableRegistry.ScopeMachine;

		[Parameter]
		public string? UserSid { get; set; }

		[Parameter]
		public SwitchParameter Volatile { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var scope = this.Scope;
			var userSid = this.UserSid;
			var volatileUserKey = this.Volatile.IsPresent;

			if (volatileUserKey && !string.Equals(scope, TboEnvironmentVariableRegistry.ScopeUser, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException("-Volatile is only valid when Scope is User.", nameof(this.Volatile));

			var spec = TboEnvironmentVariableRegistry.ResolvePathSpec(scope, userSid, volatileUserKey);

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var key = OpenRegistryKey(session.Client, spec, RegistryAccessRights.QueryValue, cancellationToken);

				if (this.Name != null)
				{
					var valueInfo = key.GetValue(this.Name, cancellationToken).GetAwaiter().GetResult();
					this.WriteObject(new TboEnvironmentVariableInfo(this.ServerName, scope, userSid, spec.KeyPath, valueInfo));
					return;
				}

				List<RegistryValueInfo> values;
				try
				{
					values = CollectValues(key, includeData: true, cancellationToken);
				}
				catch (NotSupportedException ex)
				{
					this.LogException(smb, "Get-TBOEnvironmentVariable failed to enumerate values with data", ex);
					values = CollectValues(key, includeData: false, cancellationToken);
					foreach (var valueInfo in values)
					{
						var fullInfo = key.GetValue(valueInfo.Name, cancellationToken).GetAwaiter().GetResult();
						this.WriteObject(new TboEnvironmentVariableInfo(this.ServerName, scope, userSid, spec.KeyPath, fullInfo));
					}
					return;
				}
				catch (Exception ex)
				{
					this.LogException(smb, "Get-TBOEnvironmentVariable failed to enumerate values", ex);
					throw;
				}

				foreach (var valueInfo in values)
				{
					this.WriteObject(new TboEnvironmentVariableInfo(this.ServerName, scope, userSid, spec.KeyPath, valueInfo));
				}
			});
		}
	}

	[Cmdlet(VerbsCommon.Set, "TBOEnvironmentVariable", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.Medium)]
	public sealed class SetTBOEnvironmentVariable : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipelineByPropertyName = true)]
		public string Name { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 2)]
		public string Value { get; set; } = string.Empty;

		[Parameter]
		[ValidateSet(TboEnvironmentVariableRegistry.ScopeMachine, TboEnvironmentVariableRegistry.ScopeUser)]
		public string Scope { get; set; } = TboEnvironmentVariableRegistry.ScopeMachine;

		[Parameter]
		public string? UserSid { get; set; }

		[Parameter]
		public SwitchParameter Volatile { get; set; }

		[Parameter]
		public SwitchParameter Expand { get; set; }

		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(this.Name))
				throw new ArgumentException("Environment variable name must be provided.", nameof(this.Name));

			var recordActivity = this.ResolveCacheIngestionEnabled(this.Cache);

			var scope = this.Scope;
			var userSid = this.UserSid;
			var volatileUserKey = this.Volatile.IsPresent;

			if (volatileUserKey && !string.Equals(scope, TboEnvironmentVariableRegistry.ScopeUser, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException("-Volatile is only valid when Scope is User.", nameof(this.Volatile));

			var spec = TboEnvironmentVariableRegistry.ResolvePathSpec(scope, userSid, volatileUserKey);
			var valueType = this.Expand.IsPresent ? RegistryValueType.ExpandString : RegistryValueType.String;
			var data = RegistryHelpers.EncodeValue(valueType, this.Value);

			var target = $"{this.ServerName}\\{spec.KeyPath}\\{this.Name}";
			if (!this.ShouldProcess(target, "Set environment variable"))
				return;

			RegistryValueType? beforeValueType = null;
			byte[]? beforeBytes = null;
			string? beforeReadFailure = null;
			Exception? operationFailure = null;

			try
			{
				ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					IRegistryKey key;
					try
					{
						key = OpenRegistryKey(
							session.Client,
							spec,
							RegistryAccessRights.SetValue | RegistryAccessRights.QueryValue,
							RegistryAccessRights.EnumerateSubkeys,
							cancellationToken);
					}
					catch
					{
						key = OpenRegistryKey(
							session.Client,
							spec,
							RegistryAccessRights.SetValue,
							RegistryAccessRights.EnumerateSubkeys,
							cancellationToken);
					}

					using (key)
					{
						if (recordActivity)
						{
							try
							{
								var existing = key.GetValue(this.Name, cancellationToken).GetAwaiter().GetResult();
								beforeValueType = existing.ValueType;
								if (existing.Bytes != null)
									beforeBytes = existing.Bytes;
								else if (existing.TypedValue != null)
									beforeBytes = RegistryHelpers.EncodeValue(existing.ValueType, existing.TypedValue);
								else
									beforeBytes = RegistryHelpers.EncodeValue(existing.ValueType, existing.Bytes);
							}
							catch (Exception ex)
							{
								beforeReadFailure = ex.Message;
								beforeValueType = null;
								beforeBytes = null;
							}
						}

						key.SetValue(this.Name, valueType, data, cancellationToken).GetAwaiter().GetResult();
					}
				});
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
						scope,
						userSid,
						volatileUserKey,
						beforeValueType = beforeValueType.HasValue ? (int)beforeValueType.Value : (int?)null,
						afterValueType = (int)valueType,
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
					valueName: this.Name,
					valueType: (int)valueType,
					beforeBlobKind: beforeBytes != null ? TboCacheWriteActivities.BlobKindRegistryValue : null,
					beforeBlob: beforeBytes,
					afterBlobKind: TboCacheWriteActivities.BlobKindRegistryValue,
					afterBlob: data,
					contextJson: contextJson,
					success: operationFailure == null,
					failureReason: operationFailure?.Message);
			}
		}
	}

	[Cmdlet(VerbsCommon.Remove, "TBOEnvironmentVariable", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class RemoveTBOEnvironmentVariable : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipelineByPropertyName = true)]
		public string Name { get; set; } = string.Empty;

		[Parameter]
		[ValidateSet(TboEnvironmentVariableRegistry.ScopeMachine, TboEnvironmentVariableRegistry.ScopeUser)]
		public string Scope { get; set; } = TboEnvironmentVariableRegistry.ScopeMachine;

		[Parameter]
		public string? UserSid { get; set; }

		[Parameter]
		public SwitchParameter Volatile { get; set; }

		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(this.Name))
				throw new ArgumentException("Environment variable name must be provided.", nameof(this.Name));

			var recordActivity = this.ResolveCacheIngestionEnabled(this.Cache);

			var scope = this.Scope;
			var userSid = this.UserSid;
			var volatileUserKey = this.Volatile.IsPresent;

			if (volatileUserKey && !string.Equals(scope, TboEnvironmentVariableRegistry.ScopeUser, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException("-Volatile is only valid when Scope is User.", nameof(this.Volatile));

			var spec = TboEnvironmentVariableRegistry.ResolvePathSpec(scope, userSid, volatileUserKey);

			var target = $"{this.ServerName}\\{spec.KeyPath}\\{this.Name}";
			if (!this.ShouldProcess(target, "Remove environment variable"))
				return;

			RegistryValueType? beforeValueType = null;
			byte[]? beforeBytes = null;
			string? beforeReadFailure = null;
			Exception? operationFailure = null;

			try
			{
				ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					IRegistryKey key;
					try
					{
						key = OpenRegistryKey(
							session.Client,
							spec,
							RegistryAccessRights.SetValue | RegistryAccessRights.QueryValue,
							RegistryAccessRights.EnumerateSubkeys,
							cancellationToken);
					}
					catch
					{
						key = OpenRegistryKey(
							session.Client,
							spec,
							RegistryAccessRights.SetValue,
							RegistryAccessRights.EnumerateSubkeys,
							cancellationToken);
					}

					using (key)
					{
						if (recordActivity)
						{
							try
							{
								var existing = key.GetValue(this.Name, cancellationToken).GetAwaiter().GetResult();
								beforeValueType = existing.ValueType;
								if (existing.Bytes != null)
									beforeBytes = existing.Bytes;
								else if (existing.TypedValue != null)
									beforeBytes = RegistryHelpers.EncodeValue(existing.ValueType, existing.TypedValue);
								else
									beforeBytes = RegistryHelpers.EncodeValue(existing.ValueType, existing.Bytes);
							}
							catch (Exception ex)
							{
								beforeReadFailure = ex.Message;
								beforeValueType = null;
								beforeBytes = null;
							}
						}

						key.DeleteValue(this.Name, cancellationToken).GetAwaiter().GetResult();
					}
				});
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
						scope,
						userSid,
						volatileUserKey,
						beforeValueType = beforeValueType.HasValue ? (int)beforeValueType.Value : (int?)null,
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
					action: TboCacheWriteActivities.ActionDeleteValue,
					target: target,
					path: spec.KeyPath,
					valueName: this.Name,
					valueType: beforeValueType.HasValue ? (int)beforeValueType.Value : (int?)null,
					beforeBlobKind: beforeBytes != null ? TboCacheWriteActivities.BlobKindRegistryValue : null,
					beforeBlob: beforeBytes,
					afterBlobKind: null,
					afterBlob: null,
					contextJson: contextJson,
					success: operationFailure == null,
					failureReason: operationFailure?.Message);
			}
		}
	}
}

