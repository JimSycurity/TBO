using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Provider;
using System.Threading;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegHiveItem
	{
		public TboRegHiveItem(string serverName, RegistryRootKey rootKey)
		{
			this.ServerName = serverName;
			this.RootKey = rootKey;
			this.Name = RemoteRegistryClient.GetRootName(rootKey);
		}

		public string ServerName { get; }
		public RegistryRootKey RootKey { get; }
		public string Name { get; }
		public string KeyPath => this.Name;
	}

	internal sealed class TboRegDriveInfo : PSDriveInfo
	{
		internal TboRegDriveInfo(PSDriveInfo driveInfo, string serverName)
			: base(driveInfo)
		{
			this.ServerName = serverName;
		}

		public string ServerName { get; }
	}

	/// <summary>
	/// Implements a <see cref="NavigationCmdletProvider"/> for remote registry access.
	/// </summary>
	[CmdletProvider(ProviderName, ProviderCapabilities.ShouldProcess)]
	public sealed class TboRegProvider : NavigationCmdletProvider, IPropertyCmdletProvider, IDynamicPropertyCmdletProvider, IContentCmdletProvider
	{
		public const string ProviderName = "TBO.Reg";

		private static readonly RegistryRootKey[] RootKeys = new[]
		{
			RegistryRootKey.ClassesRoot,
			RegistryRootKey.CurrentUser,
			RegistryRootKey.LocalMachine,
			RegistryRootKey.Users,
			RegistryRootKey.CurrentConfig,
			RegistryRootKey.PerformanceData,
			RegistryRootKey.PerformanceText,
			RegistryRootKey.PerformanceNlsText
		};

		private CancellationTokenSource? _cancelSource;

		protected override Collection<PSDriveInfo> InitializeDefaultDrives()
			=> new Collection<PSDriveInfo>();

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
		}

		protected override object GetChildItemsDynamicParameters(string path, bool recurse)
			=> new TboRegGetChildItemParams();

		private void BeginOperation(Action<CancellationToken> action)
		{
			var prevSource = this._cancelSource;
			var cancelSource = prevSource ??= (this._cancelSource = new CancellationTokenSource());

			try
			{
				action(cancelSource.Token);
			}
			finally
			{
				this._cancelSource = prevSource;
			}
		}

		private TResult BeginOperation<TResult>(Func<CancellationToken, TResult> func)
		{
			var prevSource = this._cancelSource;
			var cancelSource = prevSource ??= (this._cancelSource = new CancellationTokenSource());

			try
			{
				return func(cancelSource.Token);
			}
			finally
			{
				this._cancelSource = prevSource;
			}
		}

		private void ExecuteRegistryOperation(string serverName, CancellationToken token, Action<IRegistrySession> action)
		{
			var smb = GetSmbProviderInfo();
			RegistryRetryHelper.Execute(smb, serverName, token, action);
		}

		private TResult ExecuteRegistryOperation<TResult>(string serverName, CancellationToken token, Func<IRegistrySession, TResult> func)
		{
			var smb = GetSmbProviderInfo();
			return RegistryRetryHelper.Execute(smb, serverName, token, func);
		}

		protected override object NewDriveDynamicParameters()
			=> new SmbConnectionParameters();

		protected override PSDriveInfo NewDrive(PSDriveInfo drive)
		{
			var serverName = RegistryHelpers.NormalizeServerName(drive.Root);
			var smb = GetSmbProviderInfo();

			var baseParms = smb.GetConnectParametersFor(serverName, true);
			var parms = this.DynamicParameters as SmbConnectionParameters;
			if (parms != null)
			{
				parms = parms.MergeOnto(baseParms ?? SmbConnectionParameters.GetDefault());
				smb.SetConnectParameters(serverName, parms);
			}

			return new TboRegDriveInfo(drive, serverName);
		}

		protected override bool IsValidPath(string path)
		{
			if (string.IsNullOrWhiteSpace(path))
				return true;

			var normalized = path.Trim().TrimStart('\\');
			if (string.IsNullOrEmpty(normalized))
				return true;

			string rootPart = normalized.Split('\\', 2)[0].TrimEnd(':');
			if (RemoteRegistryClient.TryResolveRootKey(rootPart) != RegistryRootKey.Invalid)
				return true;

			// Accept provider root and server-scoped paths; validation happens during lookup.
			return true;
		}

		protected override bool IsItemContainer(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (RegistryHelpers.IsRootPath(providerPath) || RegistryHelpers.IsHivePath(providerPath))
				return true;

			return this.BeginOperation(token =>
				ExecuteRegistryOperation(
					drive.ServerName,
					token,
					session => RegistryHelpers.TryOpenKey(session.Client, RegistryPathParser.Parse(providerPath, nameof(path)), RegistryAccessRights.QueryValue, token) != null));
		}

		protected override bool ItemExists(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (RegistryHelpers.IsRootPath(providerPath) || RegistryHelpers.IsHivePath(providerPath))
				return true;

			return this.BeginOperation(token =>
				ExecuteRegistryOperation(
					drive.ServerName,
					token,
					session =>
					{
						var parsed = RegistryPathParser.Parse(providerPath, nameof(path));

						using var key = RegistryHelpers.TryOpenKey(session.Client, parsed, RegistryAccessRights.QueryValue, token);
						if (key != null)
							return true;

						return RegistryHelpers.TryValueExists(session.Client, parsed, token);
					}));
		}

		protected override void GetItem(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (RegistryHelpers.IsRootPath(providerPath))
				return;

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				if (parsed.IsRoot)
				{
					var item = new TboRegHiveItem(drive.ServerName, parsed.RootKey);
					this.WriteItemObject(item, parsed.RootName, true);
					return;
				}

				ExecuteRegistryOperation(drive.ServerName, token, session =>
				{
					using var key = RegistryHelpers.TryOpenKey(session.Client, parsed, RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys, token);
					if (key != null)
					{
						var info = key.QueryInfo(token).GetAwaiter().GetResult();
						this.WriteItemObject(new TboRegistryKeyInfo(drive.ServerName, parsed.KeyPath, info), parsed.KeyPath, true);
						return;
					}

					if (RegistryHelpers.TryGetValue(session.Client, parsed, token, out var valueInfo, out var parentKeyPath))
					{
						var itemPath = RegistryHelpers.CombineProviderPath(parentKeyPath, RegistryHelpers.NormalizeValueName(valueInfo.Name));
						this.WriteItemObject(new TboRegistryValueInfo(drive.ServerName, parentKeyPath, valueInfo), itemPath, false);
						return;
					}

					throw new ItemNotFoundException($"Registry path not found: {parsed.KeyPath}");
				});
			});
		}

		protected override void GetChildItems(string path, bool recurse)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (RegistryHelpers.IsRootPath(providerPath))
			{
				foreach (var rootKey in RootKeys)
				{
					var item = new TboRegHiveItem(drive.ServerName, rootKey);
					this.WriteItemObject(item, item.Name, true);
				}
				return;
			}

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				ExecuteRegistryOperation(drive.ServerName, token, session =>
				{
					var childParams = this.DynamicParameters as TboRegGetChildItemParams;
					var includeValues = childParams?.IncludeValues.IsPresent ?? false;
					var includeData = childParams?.IncludeData.IsPresent ?? false;
					var includeProperties = childParams?.IncludeProperties.IsPresent ?? false;
					if (includeData)
						includeValues = true;

					var access = RegistryAccessRights.EnumerateSubkeys;
					if (includeValues)
						access |= RegistryAccessRights.QueryValue;

					using var key = RegistryHelpers.OpenRegistryKey(session.Client, parsed, access, token);

					foreach (var subkey in RegistryHelpers.EnumerateSubkeys(key, token))
					{
						var propertyNames = Array.Empty<string>();
						if (includeProperties)
						{
							try
							{
								using var subkeyHandle = key.OpenSubkey(subkey.KeyName, RegistryAccessRights.QueryValue, RegistryHelpers.BackupOptions, token).GetAwaiter().GetResult();
								propertyNames = RegistryHelpers.CollectValueNames(subkeyHandle, token);
							}
							catch (OperationCanceledException)
							{
								throw;
							}
							catch
							{
							}
						}

						var item = new TboRegistrySubkeyInfo(drive.ServerName, parsed.KeyPath, subkey, propertyNames);
						this.WriteItemObject(item, item.KeyPath, true);
					}

					if (includeValues)
					{
						foreach (var value in RegistryHelpers.EnumerateValues(key, includeData, token))
						{
							var normalizedName = RegistryHelpers.NormalizeValueName(value.Name);
							var valueInfo = new TboRegistryValueInfo(drive.ServerName, parsed.KeyPath, value);
							this.WriteItemObject(valueInfo, RegistryHelpers.CombineProviderPath(parsed.KeyPath, normalizedName), false);
						}
					}
				});
			});
		}

		protected override bool HasChildItems(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (RegistryHelpers.IsRootPath(providerPath))
				return RootKeys.Length > 0;

			return this.BeginOperation(token =>
				ExecuteRegistryOperation(
					drive.ServerName,
					token,
					session =>
					{
						var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
						using var key = RegistryHelpers.OpenRegistryKey(session.Client, parsed, RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys, token);
						var info = key.QueryInfo(token).GetAwaiter().GetResult();
						return info.SubkeyCount > 0 || info.ValueCount > 0;
					}));
		}

		protected override void NewItem(string path, string itemTypeName, object newItemValue)
		{
			if (!string.IsNullOrWhiteSpace(itemTypeName)
				&& !string.Equals(itemTypeName, "Key", StringComparison.OrdinalIgnoreCase))
				throw new NotSupportedException($"Unsupported item type '{itemTypeName}'. Only registry keys are supported.");

			var providerPath = ResolveProviderPath(path, out var drive);
			if (RegistryHelpers.IsRootPath(providerPath) || RegistryHelpers.IsHivePath(providerPath))
				throw new InvalidOperationException("Cannot create a registry hive.");

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				if (parsed.IsRoot)
					throw new InvalidOperationException("Cannot create a root registry key.");

				var subkeyPath = parsed.SubkeyPath!;
				var parentPath = RegistryPath.GetParentKeyNameFromPath(subkeyPath);
				var subkeyName = RegistryPath.GetSubkeyNameFromPath(subkeyPath);
				var parentSpec = new RegistryPathSpec(parsed.RootKey, parsed.RootName, parentPath);

				ExecuteRegistryOperation(drive.ServerName, token, session =>
				{
					using var parentKey = RegistryHelpers.OpenRegistryKey(
						session.Client,
						parentSpec,
						RegistryAccessRights.CreateSubkey,
						RegistryAccessRights.EnumerateSubkeys,
						token);

					var createAccess = RegistryAccessRights.CreateSubkey | RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys;
					using var created = parentKey.CreateSubkey(subkeyName, createAccess, RegistryHelpers.BackupOptions, token).GetAwaiter().GetResult();
					var info = created.QueryInfo(token).GetAwaiter().GetResult();
					this.WriteItemObject(new TboRegistryKeyInfo(drive.ServerName, parsed.KeyPath, info), parsed.KeyPath, true);
				});
			});
		}

		protected override void RemoveItem(string path, bool recurse)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (RegistryHelpers.IsRootPath(providerPath) || RegistryHelpers.IsHivePath(providerPath))
				throw new InvalidOperationException("Cannot remove a registry hive.");

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				ExecuteRegistryOperation(drive.ServerName, token, session =>
				{
					var existingKey = RegistryHelpers.TryOpenKey(session.Client, parsed, RegistryAccessRights.EnumerateSubkeys, token);
					if (existingKey != null)
					{
						existingKey.Dispose();
						RegistryHelpers.RemoveRegistryKey(session.Client, parsed, recurse, token);
						return;
					}

					if (RegistryHelpers.TryValueExists(session.Client, parsed, token))
					{
						RegistryHelpers.RemoveRegistryValue(session.Client, parsed, token);
						return;
					}

					throw new ItemNotFoundException($"Registry path not found: {parsed.KeyPath}");
				});
			});
		}

		public void GetProperty(string path, Collection<string> providerSpecificPickList)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (RegistryHelpers.IsRootPath(providerPath) || RegistryHelpers.IsHivePath(providerPath))
				throw new ArgumentException("Path must be a registry key.", nameof(path));

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				ExecuteRegistryOperation(drive.ServerName, token, session =>
				{
					using var key = RegistryHelpers.OpenRegistryKey(session.Client, parsed, RegistryAccessRights.QueryValue, token);

					var output = new PSObject();
					if (providerSpecificPickList != null && providerSpecificPickList.Count > 0)
					{
						foreach (var entry in providerSpecificPickList)
						{
							var valueName = RegistryHelpers.DenormalizeValueName(entry);
							var valueInfo = key.GetValue(valueName, token).GetAwaiter().GetResult();
							output.Properties.Add(new PSNoteProperty(RegistryHelpers.NormalizeValueName(valueInfo.Name), valueInfo.TypedValue));
						}
					}
					else
					{
						var values = RegistryHelpers.EnumerateValues(key, includeData: true, token);
						foreach (var valueInfo in values)
						{
							output.Properties.Add(new PSNoteProperty(RegistryHelpers.NormalizeValueName(valueInfo.Name), valueInfo.TypedValue));
						}
					}

					this.WritePropertyObject(output, parsed.KeyPath);
				});
			});
		}

		public object GetPropertyDynamicParameters(string path, Collection<string> providerSpecificPickList)
			=> null;

		public void SetProperty(string path, PSObject propertyValue)
		{
			if (propertyValue == null)
				return;

			var providerPath = ResolveProviderPath(path, out var drive);
			if (RegistryHelpers.IsRootPath(providerPath) || RegistryHelpers.IsHivePath(providerPath))
				throw new ArgumentException("Path must be a registry key.", nameof(path));

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				ExecuteRegistryOperation(drive.ServerName, token, session =>
				{
					using var key = RegistryHelpers.OpenRegistryKey(
						session.Client,
						parsed,
						RegistryAccessRights.SetValue,
						RegistryAccessRights.EnumerateSubkeys,
						token);

					var setParams = this.DynamicParameters as TboRegSetPropertyParams;
					foreach (var entry in EnumeratePropertyValues(propertyValue))
					{
						var valueName = RegistryHelpers.DenormalizeValueName(entry.Key);
						var valueType = RegistryHelpers.ResolveValueType(entry.Value, setParams?.Type);
						var data = RegistryHelpers.EncodeValue(valueType, entry.Value);
						key.SetValue(valueName, valueType, data, token).GetAwaiter().GetResult();
					}
				});
			});
		}

		public object SetPropertyDynamicParameters(string path, PSObject propertyValue)
			=> new TboRegSetPropertyParams();

		public void ClearProperty(string path, Collection<string> propertyToClear)
			=> throw new NotSupportedException("Clearing registry values is not supported. Use Remove-ItemProperty instead.");

		public object ClearPropertyDynamicParameters(string path, Collection<string> propertyToClear)
			=> null;

		public void NewProperty(string path, string propertyName, string propertyTypeName, object value)
			=> throw new NotSupportedException("New-ItemProperty is not supported. Use Set-ItemProperty instead.");

		public object NewPropertyDynamicParameters(string path, string propertyName, string propertyTypeName, object value)
			=> null;

		public void RemoveProperty(string path, string propertyName)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (RegistryHelpers.IsRootPath(providerPath) || RegistryHelpers.IsHivePath(providerPath))
				throw new ArgumentException("Path must be a registry key.", nameof(path));

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				ExecuteRegistryOperation(drive.ServerName, token, session =>
				{
					using var key = RegistryHelpers.OpenRegistryKey(
						session.Client,
						parsed,
						RegistryAccessRights.SetValue,
						RegistryAccessRights.EnumerateSubkeys,
						token);
					var valueName = RegistryHelpers.DenormalizeValueName(propertyName);
					key.DeleteValue(valueName, token).GetAwaiter().GetResult();
				});
			});
		}

		public object RemovePropertyDynamicParameters(string path, string propertyName)
			=> null;

		public void RenameProperty(string path, string sourceProperty, string destinationProperty)
			=> throw new NotSupportedException("Renaming registry values is not supported.");

		public object RenamePropertyDynamicParameters(string path, string sourceProperty, string destinationProperty)
			=> null;

		public void CopyProperty(string sourcePath, string sourceProperty, string destinationPath, string destinationProperty)
			=> throw new NotSupportedException("Copying registry values is not supported.");

		public object CopyPropertyDynamicParameters(string sourcePath, string sourceProperty, string destinationPath, string destinationProperty)
			=> null;

		public void MoveProperty(string sourcePath, string sourceProperty, string destinationPath, string destinationProperty)
			=> throw new NotSupportedException("Moving registry values is not supported.");

		public object MovePropertyDynamicParameters(string sourcePath, string sourceProperty, string destinationPath, string destinationProperty)
			=> null;

		public void ClearContent(string path)
			=> throw new NotSupportedException("Clearing registry values is not supported. Use Remove-ItemProperty instead.");

		public object ClearContentDynamicParameters(string path)
			=> null;

		public IContentReader GetContentReader(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (RegistryHelpers.IsRootPath(providerPath) || RegistryHelpers.IsHivePath(providerPath))
				throw new ArgumentException("Path must be a registry value.", nameof(path));

			return this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				return ExecuteRegistryOperation(
					drive.ServerName,
					token,
					session =>
					{
						if (RegistryHelpers.TryGetValue(session.Client, parsed, token, out var valueInfo, out _))
							return (IContentReader)new TboRegContentReader(valueInfo);

						using var key = RegistryHelpers.TryOpenKey(session.Client, parsed, RegistryAccessRights.QueryValue, token);
						if (key != null)
							throw new NotSupportedException("Get-Content requires a registry value path. Use Get-ChildItem or Get-ItemProperty for keys.");

						throw new ItemNotFoundException($"Registry value not found: {parsed.KeyPath}");
					});
			});
		}

		public object GetContentReaderDynamicParameters(string path)
			=> null;

		public IContentWriter GetContentWriter(string path)
			=> throw new NotSupportedException("Writing registry values with Set-Content is not supported. Use Set-ItemProperty instead.");

		public object GetContentWriterDynamicParameters(string path)
			=> null;

		private string ResolveProviderPath(string path, out TboRegDriveInfo driveInfo)
		{
			driveInfo = this.PSDriveInfo as TboRegDriveInfo
				?? throw new ArgumentException($"Path must be a {ProviderName} PSDrive path: {path}", nameof(path));

			var providerPath = path ?? string.Empty;
			var providerQualifierIndex = providerPath.IndexOf("::", StringComparison.Ordinal);
			bool hasQualifier = providerQualifierIndex >= 0;
			if (hasQualifier)
				providerPath = providerPath.Substring(providerQualifierIndex + 2);

			var drivePrefix = driveInfo.Name + ":";
			bool hasDrivePrefix = providerPath.StartsWith(drivePrefix, StringComparison.OrdinalIgnoreCase);
			if (hasDrivePrefix)
				providerPath = providerPath.Substring(drivePrefix.Length);

			providerPath = providerPath.TrimStart('\\');

			var root = driveInfo.Root?.TrimStart('\\').TrimEnd('\\');
			if (!string.IsNullOrEmpty(root))
			{
				if (providerPath.Equals(root, StringComparison.OrdinalIgnoreCase))
					return string.Empty;

				var prefix = root + "\\";
				if (providerPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
					providerPath = providerPath.Substring(prefix.Length);
			}

			if (!hasQualifier && !hasDrivePrefix && !RegistryHelpers.IsRootedRegistryPath(providerPath))
			{
				var current = driveInfo.CurrentLocation?.TrimStart('\\');
				if (!string.IsNullOrEmpty(current))
				{
					if (string.IsNullOrEmpty(providerPath) || providerPath == ".")
					{
						providerPath = current;
					}
					else
					{
						if (providerPath.StartsWith(".\\", StringComparison.Ordinal))
							providerPath = providerPath.Substring(2);

						providerPath = RegistryHelpers.CombineProviderPath(current, providerPath);
					}
				}
			}

			return providerPath;
		}

		private SmbProviderInfo GetSmbProviderInfo()
			=> (SmbProviderInfo)this.SessionState.Provider.GetOne(SmbProvider.ProviderName);

		private static IEnumerable<KeyValuePair<string, object?>> EnumeratePropertyValues(PSObject propertyValue)
		{
			if (propertyValue.BaseObject is IDictionary dictionary)
			{
				foreach (DictionaryEntry entry in dictionary)
				{
					var name = entry.Key?.ToString() ?? string.Empty;
					yield return new KeyValuePair<string, object?>(name, entry.Value);
				}
				yield break;
			}

			foreach (var property in propertyValue.Properties)
			{
				if (property == null)
					continue;

				yield return new KeyValuePair<string, object?>(property.Name ?? string.Empty, property.Value);
			}
		}
	}

	internal sealed class TboRegGetChildItemParams
	{
		[Parameter]
		public SwitchParameter IncludeValues { get; set; }

		[Parameter]
		public SwitchParameter IncludeProperties { get; set; }

		[Parameter]
		public SwitchParameter IncludeData { get; set; }
	}

	internal sealed class TboRegSetPropertyParams
	{
		[Parameter]
		public RegistryValueType? Type { get; set; }
	}

	internal sealed class TboRegContentReader : IContentReader
	{
		private readonly object? _content;
		private bool _completed;

		internal TboRegContentReader(RegistryValueInfo valueInfo)
		{
			this._content = valueInfo.TypedValue ?? (object?)valueInfo.Bytes;
		}

		public void Close()
			=> Dispose();

		public void Dispose()
		{
		}

		public IList Read(long readCount)
		{
			if (this._completed)
				return Array.Empty<object>();

			this._completed = true;
			if (this._content is null)
				return Array.Empty<object>();

			return new object[] { this._content };
		}

		public void Seek(long offset, SeekOrigin origin)
			=> throw new NotSupportedException("Registry values do not support seeking.");
	}
}
