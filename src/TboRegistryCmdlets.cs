using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Text.RegularExpressions;
using System.Threading;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegistryKeyInfo
	{
		public TboRegistryKeyInfo(string serverName, string keyPath, RegistryKeyInfo info)
		{
			this.ServerName = serverName;
			this.KeyPath = keyPath;
			this.ClassName = info.ClassName;
			this.SubkeyCount = info.SubkeyCount;
			this.MaxSubkeyLength = info.MaxSubkeyLength;
			this.MaxClassLength = info.MaxClassLength;
			this.ValueCount = info.ValueCount;
			this.MaxValueNameLength = info.MaxValueNameLength;
			this.MaxValueDataLength = info.MaxValueDataLength;
			this.SecurityDescriptorLength = info.SecurityDescriptorLength;
			this.LastWriteTime = info.LastWriteTime;
		}

		public string ServerName { get; }
		public string KeyPath { get; }
		public string? ClassName { get; }
		public int SubkeyCount { get; }
		public int MaxSubkeyLength { get; }
		public int MaxClassLength { get; }
		public int ValueCount { get; }
		public int MaxValueNameLength { get; }
		public int MaxValueDataLength { get; }
		public int SecurityDescriptorLength { get; }
		public DateTime LastWriteTime { get; }
	}

	public sealed class TboRegistrySubkeyInfo
	{
		public TboRegistrySubkeyInfo(string serverName, string parentKeyPath, RegistrySubkeyInfo info, IReadOnlyList<string>? propertyNames = null)
		{
			this.ServerName = serverName;
			this.ParentKeyPath = parentKeyPath;
			this.Name = info.KeyName;
			this.KeyPath = string.IsNullOrEmpty(parentKeyPath) ? info.KeyName : $"{parentKeyPath}\\{info.KeyName}";
			this.ClassName = info.ClassName;
			this.Property = propertyNames ?? Array.Empty<string>();
		}

		public string ServerName { get; }
		public string ParentKeyPath { get; }
		public string Name { get; }
		public string KeyPath { get; }
		public string? ClassName { get; }
		public IReadOnlyList<string> Property { get; }
	}

	public sealed class TboRegistryValueInfo
	{
		public TboRegistryValueInfo(string serverName, string keyPath, RegistryValueInfo info)
		{
			this.ServerName = serverName;
			this.KeyPath = keyPath;
			this.Name = info.Name;
			this.ValueType = info.ValueType;
			this.DataLength = info.DataLength;
			this.Bytes = info.Bytes;
			this.Value = info.TypedValue;
		}

		public string ServerName { get; }
		public string KeyPath { get; }
		public string Name { get; }
		public RegistryValueType ValueType { get; }
		public int DataLength { get; }
		public byte[]? Bytes { get; }
		public object? Value { get; }
	}

	public abstract class TboRegCmdlet : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			this.ProcessRecord(smb, this._cancelSource.Token);
		}

		protected abstract void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken);

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		protected void ExecuteRegistryOperation(
			ISmbProviderInfo smb,
			CancellationToken cancellationToken,
			Action<IRegistrySession> action)
		{
			RegistryRetryHelper.Execute(smb, this.ServerName, cancellationToken, action);
		}

		protected TResult ExecuteRegistryOperation<TResult>(
			ISmbProviderInfo smb,
			CancellationToken cancellationToken,
			Func<IRegistrySession, TResult> func)
		{
			return RegistryRetryHelper.Execute(smb, this.ServerName, cancellationToken, func);
		}
		protected static RegistryPathSpec ParseRegistryPath(string path, string paramName)
		{
			return RegistryPathParser.Parse(path, paramName);
		}

		protected IRegistryKey OpenRegistryKey(
			IRegistryClient client,
			RegistryPathSpec path,
			RegistryAccessRights access,
			RegistryAccessRights? rootAccess,
			CancellationToken cancellationToken)
		{
			return RegistryHelpers.OpenRegistryKey(client, path, access, rootAccess, cancellationToken);
		}

		protected IRegistryKey OpenRegistryKey(
			IRegistryClient client,
			RegistryPathSpec path,
			RegistryAccessRights access,
			CancellationToken cancellationToken)
			=> RegistryHelpers.OpenRegistryKey(client, path, access, cancellationToken);

		protected static List<RegistrySubkeyInfo> CollectSubkeys(IRegistryKey key, CancellationToken cancellationToken)
			=> RegistryHelpers.CollectSubkeys(key, cancellationToken);

		protected static List<RegistryValueInfo> CollectValues(IRegistryKey key, bool includeData, CancellationToken cancellationToken)
			=> RegistryHelpers.CollectValues(key, includeData, cancellationToken);
	}

	[Cmdlet(VerbsCommon.Get, "TBORegSessions")]
	[OutputType(typeof(string))]
	public sealed class GetTBORegSessions : TboRegCmdlet
	{
		private static readonly Regex UserSidRegex = new(@"^S-1-5-21-\d+-\d+-\d+-\d+$", RegexOptions.CultureInvariant);
		private static readonly HashSet<string> SystemSids = new(StringComparer.OrdinalIgnoreCase)
		{
			"S-1-5-18",
			"S-1-5-19",
			"S-1-5-20"
		};

		[Parameter]
		public SwitchParameter ResolveSid { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			if (this.ResolveSid.IsPresent)
				throw new NotSupportedException("ResolveSid is not implemented yet.");

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var rootKey = session.Client.OpenRootKey(RegistryRootKey.Users, RegistryAccessRights.EnumerateSubkeys, cancellationToken).GetAwaiter().GetResult();

				List<RegistrySubkeyInfo> subkeys;
				try
				{
					subkeys = CollectSubkeys(rootKey, cancellationToken);
				}
				catch (Exception ex)
				{
					this.LogException(smb, "Get-TBORegSessions failed to enumerate HKEY_USERS", ex);
					throw;
				}

				foreach (var subkey in subkeys)
				{
					var sid = subkey.KeyName;
					if (!UserSidRegex.IsMatch(sid))
						continue;
					if (SystemSids.Contains(sid))
						continue;

					this.WriteObject(sid);
				}
			});
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBORegKey")]
	public sealed class GetTBORegKey : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

		[Parameter]
		public SwitchParameter IncludeClass { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var key = OpenRegistryKey(
					session.Client,
					parsedPath,
					RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys,
					cancellationToken);

				var info = key.QueryInfo(this.IncludeClass.IsPresent, cancellationToken).GetAwaiter().GetResult();
				this.WriteObject(new TboRegistryKeyInfo(this.ServerName, parsedPath.KeyPath, info));
			});
		}
	}

	[Cmdlet(VerbsCommon.New, "TBORegKey", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.Medium)]
	public sealed class NewTBORegKey : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
			if (parsedPath.IsRoot)
				throw new InvalidOperationException("Cannot create a root key.");

			var target = $"{this.ServerName}\\{parsedPath.KeyPath}";
			if (!this.ShouldProcess(target, "Create registry key"))
				return;

			var subkeyPath = parsedPath.SubkeyPath!;
			var parentPath = RegistryPath.GetParentKeyNameFromPath(subkeyPath);
			var subkeyName = RegistryPath.GetSubkeyNameFromPath(subkeyPath);
			var parentSpec = new RegistryPathSpec(parsedPath.RootKey, parsedPath.RootName, parentPath);

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var parentKey = OpenRegistryKey(
					session.Client,
					parentSpec,
					RegistryAccessRights.CreateSubkey,
					RegistryAccessRights.EnumerateSubkeys,
					cancellationToken);

				var createAccess = RegistryAccessRights.CreateSubkey | RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys;
				using var created = parentKey.CreateSubkey(subkeyName, createAccess, RegistryHelpers.BackupOptions, cancellationToken).GetAwaiter().GetResult();
				this.WriteObject(new TboRegistryKeyInfo(this.ServerName, parsedPath.KeyPath, created.QueryInfo(cancellationToken).GetAwaiter().GetResult()));
			});
		}
	}

	[Cmdlet(VerbsCommon.Remove, "TBORegKey", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class RemoveTBORegKey : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
			if (parsedPath.IsRoot)
				throw new InvalidOperationException("Cannot remove a root key.");

			var target = $"{this.ServerName}\\{parsedPath.KeyPath}";
			if (!this.ShouldProcess(target, "Remove registry key"))
				return;

			var subkeyPath = parsedPath.SubkeyPath!;
			var parentPath = RegistryPath.GetParentKeyNameFromPath(subkeyPath);
			var subkeyName = RegistryPath.GetSubkeyNameFromPath(subkeyPath);
			var parentSpec = new RegistryPathSpec(parsedPath.RootKey, parsedPath.RootName, parentPath);

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var parentKey = OpenRegistryKey(
					session.Client,
					parentSpec,
					RegistryAccessRights.CreateSubkey,
					RegistryAccessRights.EnumerateSubkeys,
					cancellationToken);

				parentKey.DeleteSubkey(subkeyName, cancellationToken).GetAwaiter().GetResult();
			});
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBORegValue")]
	public sealed class GetTBORegValue : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

		[Parameter(Position = 2, ValueFromPipelineByPropertyName = true)]
		public string? Name { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var key = OpenRegistryKey(session.Client, parsedPath, RegistryAccessRights.QueryValue, cancellationToken);

				var info = key.QueryInfo(cancellationToken).GetAwaiter().GetResult();
				if (this.Name != null)
				{
					var valueInfo = key.GetValue(this.Name, cancellationToken).GetAwaiter().GetResult();
					this.WriteObject(new TboRegistryValueInfo(this.ServerName, parsedPath.KeyPath, valueInfo));
					return;
				}

				if (info.ValueCount == 0)
					return;

				List<RegistryValueInfo> values;
				try
				{
					values = CollectValues(key, includeData: true, cancellationToken);
				}
				catch (NotSupportedException ex)
				{
					this.LogException(smb, "Get-TBORegValue failed to enumerate values with data", ex);
					values = CollectValues(key, includeData: false, cancellationToken);
					foreach (var valueInfo in values)
					{
						var fullInfo = key.GetValue(valueInfo.Name, cancellationToken).GetAwaiter().GetResult();
						this.WriteObject(new TboRegistryValueInfo(this.ServerName, parsedPath.KeyPath, fullInfo));
					}
					return;
				}
				catch (Exception ex)
				{
					this.LogException(smb, "Get-TBORegValue failed to enumerate values", ex);
					throw;
				}

				foreach (var valueInfo in values)
				{
					this.WriteObject(new TboRegistryValueInfo(this.ServerName, parsedPath.KeyPath, valueInfo));
				}
			});
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBORegChildItem")]
	[OutputType(typeof(TboRegistrySubkeyInfo))]
	[OutputType(typeof(TboRegistryValueInfo))]
	public sealed class GetTBORegChildItem : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

		[Parameter]
		public SwitchParameter IncludeSubkeys { get; set; }

		[Parameter]
		public SwitchParameter IncludeValues { get; set; }

		[Parameter]
		public SwitchParameter IncludeData { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			bool includeSubkeys = this.IncludeSubkeys.IsPresent;
			bool includeValues = this.IncludeValues.IsPresent;
			if (!includeSubkeys && !includeValues)
			{
				includeSubkeys = true;
				includeValues = true;
			}

			var access = RegistryAccessRights.None;
			if (includeSubkeys)
				access |= RegistryAccessRights.EnumerateSubkeys;
			if (includeValues)
				access |= RegistryAccessRights.QueryValue;

			var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var key = OpenRegistryKey(session.Client, parsedPath, access, cancellationToken);

				if (includeSubkeys)
				{
					List<RegistrySubkeyInfo> subkeys;
					try
					{
						subkeys = CollectSubkeys(key, cancellationToken);
					}
					catch (Exception ex)
					{
						this.LogException(smb, "Get-TBORegChildItem failed to enumerate subkeys", ex);
						throw;
					}

					foreach (var subkey in subkeys)
					{
						this.WriteObject(new TboRegistrySubkeyInfo(this.ServerName, parsedPath.KeyPath, subkey));
					}
				}

				if (includeValues)
				{
					List<RegistryValueInfo> values;
					try
					{
						values = CollectValues(key, includeData: this.IncludeData.IsPresent, cancellationToken);
					}
					catch (NotSupportedException ex)
					{
						this.LogException(smb, "Get-TBORegChildItem failed to enumerate values with data", ex);
						values = CollectValues(key, includeData: false, cancellationToken);
						foreach (var valueInfo in values)
						{
							var fullInfo = key.GetValue(valueInfo.Name, cancellationToken).GetAwaiter().GetResult();
							this.WriteObject(new TboRegistryValueInfo(this.ServerName, parsedPath.KeyPath, fullInfo));
						}
						return;
					}
					catch (Exception ex)
					{
						this.LogException(smb, "Get-TBORegChildItem failed to enumerate values", ex);
						throw;
					}

					foreach (var valueInfo in values)
					{
						this.WriteObject(new TboRegistryValueInfo(this.ServerName, parsedPath.KeyPath, valueInfo));
					}
				}
			});
		}
	}

	[Cmdlet(VerbsCommon.Set, "TBORegValue", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.Medium)]
	public sealed class SetTBORegValue : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 2, ValueFromPipelineByPropertyName = true)]
		public string? Name { get; set; }

		[Parameter(Mandatory = true, Position = 3)]
		public object Value { get; set; } = null!;

		[Parameter]
		public RegistryValueType? Type { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
			var valueType = RegistryHelpers.ResolveValueType(this.Value, this.Type);
			var data = RegistryHelpers.EncodeValue(valueType, this.Value);

			var target = $"{this.ServerName}\\{parsedPath.KeyPath}\\{this.Name}";
			if (!this.ShouldProcess(target, "Set registry value"))
				return;

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var key = OpenRegistryKey(
					session.Client,
					parsedPath,
					RegistryAccessRights.SetValue,
					RegistryAccessRights.EnumerateSubkeys,
					cancellationToken);

				key.SetValue(this.Name, valueType, data, cancellationToken).GetAwaiter().GetResult();
			});
		}

	}

	[Cmdlet(VerbsCommon.Remove, "TBORegValue", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class RemoveTBORegValue : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 2, ValueFromPipelineByPropertyName = true)]
		public string? Name { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
			var target = $"{this.ServerName}\\{parsedPath.KeyPath}\\{this.Name}";
			if (!this.ShouldProcess(target, "Remove registry value"))
				return;

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var key = OpenRegistryKey(
					session.Client,
					parsedPath,
					RegistryAccessRights.SetValue,
					RegistryAccessRights.EnumerateSubkeys,
					cancellationToken);

				key.DeleteValue(this.Name, cancellationToken).GetAwaiter().GetResult();
			});
		}
	}
}
