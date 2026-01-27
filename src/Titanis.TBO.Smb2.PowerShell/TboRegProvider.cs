using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Provider;
using System.Text;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;

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
		private const RegistryKeyOptions BackupOptions = RegistryKeyOptions.BackupRestore;
		private const string DefaultValueName = "(Default)";

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

		protected override object NewDriveDynamicParameters()
			=> new SmbConnectionParameters();

		protected override PSDriveInfo NewDrive(PSDriveInfo drive)
		{
			var serverName = NormalizeServerName(drive.Root);
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
			if (IsRootPath(providerPath) || IsHivePath(providerPath))
				return true;

			return this.BeginOperation(token =>
			{
				using var session = OpenRegistrySession(drive.ServerName, token);
				return TryOpenKey(session.Client, RegistryPathParser.Parse(providerPath, nameof(path)), RegistryAccessRights.QueryValue, token) != null;
			});
		}

		protected override bool ItemExists(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath) || IsHivePath(providerPath))
				return true;

			return this.BeginOperation(token =>
			{
				using var session = OpenRegistrySession(drive.ServerName, token);
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));

				using var key = TryOpenKey(session.Client, parsed, RegistryAccessRights.QueryValue, token);
				if (key != null)
					return true;

				return TryValueExists(session.Client, parsed, token);
			});
		}

		protected override void GetItem(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath))
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

				using var session = OpenRegistrySession(drive.ServerName, token);
				using var key = TryOpenKey(session.Client, parsed, RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys, token);
				if (key != null)
				{
					var info = key.QueryInfo(token).GetAwaiter().GetResult();
					this.WriteItemObject(new TboRegistryKeyInfo(drive.ServerName, parsed.KeyPath, info), parsed.KeyPath, true);
					return;
				}

				if (TryGetValue(session.Client, parsed, token, out var valueInfo, out var parentKeyPath))
				{
					var itemPath = CombineProviderPath(parentKeyPath, NormalizeValueName(valueInfo.Name));
					this.WriteItemObject(new TboRegistryValueInfo(drive.ServerName, parentKeyPath, valueInfo), itemPath, false);
					return;
				}

				throw new ItemNotFoundException($"Registry path not found: {parsed.KeyPath}");
			});
		}

		protected override void GetChildItems(string path, bool recurse)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath))
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
				using var session = OpenRegistrySession(drive.ServerName, token);
				using var key = OpenRegistryKey(session.Client, parsed, RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue, token);
				var childParams = this.DynamicParameters as TboRegGetChildItemParams;
				var includeValues = childParams?.IncludeValues.IsPresent ?? false;
				var includeData = childParams?.IncludeData.IsPresent ?? false;
				if (includeData)
					includeValues = true;

				foreach (var subkey in EnumerateSubkeys(key, token))
				{
					var propertyNames = Array.Empty<string>();
					try
					{
						using var subkeyHandle = key.OpenSubkey(subkey.KeyName, RegistryAccessRights.QueryValue, BackupOptions, token).GetAwaiter().GetResult();
						propertyNames = CollectValueNames(subkeyHandle, token);
					}
					catch (OperationCanceledException)
					{
						throw;
					}
					catch
					{
					}

					var item = new TboRegistrySubkeyInfo(drive.ServerName, parsed.KeyPath, subkey, propertyNames);
					this.WriteItemObject(item, item.KeyPath, true);
				}

				if (includeValues)
				{
					foreach (var value in EnumerateValues(key, includeData, token))
					{
						var normalizedName = NormalizeValueName(value.Name);
						var valueInfo = new TboRegistryValueInfo(drive.ServerName, parsed.KeyPath, value);
						this.WriteItemObject(valueInfo, CombineProviderPath(parsed.KeyPath, normalizedName), false);
					}
				}
			});
		}

		protected override bool HasChildItems(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath))
				return RootKeys.Length > 0;

			return this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				using var session = OpenRegistrySession(drive.ServerName, token);
				using var key = OpenRegistryKey(session.Client, parsed, RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys, token);
				var info = key.QueryInfo(token).GetAwaiter().GetResult();
				return info.SubkeyCount > 0 || info.ValueCount > 0;
			});
		}

		protected override void NewItem(string path, string itemTypeName, object newItemValue)
		{
			if (!string.IsNullOrWhiteSpace(itemTypeName)
				&& !string.Equals(itemTypeName, "Key", StringComparison.OrdinalIgnoreCase))
				throw new NotSupportedException($"Unsupported item type '{itemTypeName}'. Only registry keys are supported.");

			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath) || IsHivePath(providerPath))
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

				using var session = OpenRegistrySession(drive.ServerName, token);
				using var parentKey = OpenRegistryKey(
					session.Client,
					parentSpec,
					RegistryAccessRights.CreateSubkey,
					RegistryAccessRights.EnumerateSubkeys,
					token);

				var createAccess = RegistryAccessRights.CreateSubkey | RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys;
				using var created = parentKey.CreateSubkey(subkeyName, createAccess, BackupOptions, token).GetAwaiter().GetResult();
				var info = created.QueryInfo(token).GetAwaiter().GetResult();
				this.WriteItemObject(new TboRegistryKeyInfo(drive.ServerName, parsed.KeyPath, info), parsed.KeyPath, true);
			});
		}

		protected override void RemoveItem(string path, bool recurse)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath) || IsHivePath(providerPath))
				throw new InvalidOperationException("Cannot remove a registry hive.");

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				using var session = OpenRegistrySession(drive.ServerName, token);

				var existingKey = TryOpenKey(session.Client, parsed, RegistryAccessRights.EnumerateSubkeys, token);
				if (existingKey != null)
				{
					existingKey.Dispose();
					RemoveRegistryKey(session.Client, parsed, recurse, token);
					return;
				}

				if (TryValueExists(session.Client, parsed, token))
				{
					RemoveRegistryValue(session.Client, parsed, token);
					return;
				}

				throw new ItemNotFoundException($"Registry path not found: {parsed.KeyPath}");
			});
		}

		public void GetProperty(string path, Collection<string> providerSpecificPickList)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath) || IsHivePath(providerPath))
				throw new ArgumentException("Path must be a registry key.", nameof(path));

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				using var session = OpenRegistrySession(drive.ServerName, token);
				using var key = OpenRegistryKey(session.Client, parsed, RegistryAccessRights.QueryValue, token);

				var output = new PSObject();
				if (providerSpecificPickList != null && providerSpecificPickList.Count > 0)
				{
					foreach (var entry in providerSpecificPickList)
					{
						var valueName = DenormalizeValueName(entry);
						var valueInfo = key.GetValue(valueName, token).GetAwaiter().GetResult();
						output.Properties.Add(new PSNoteProperty(NormalizeValueName(valueInfo.Name), valueInfo.TypedValue));
					}
				}
				else
				{
					var values = EnumerateValues(key, includeData: true, token);
					foreach (var valueInfo in values)
					{
						output.Properties.Add(new PSNoteProperty(NormalizeValueName(valueInfo.Name), valueInfo.TypedValue));
					}
				}

				this.WritePropertyObject(output, parsed.KeyPath);
			});
		}

		public object GetPropertyDynamicParameters(string path, Collection<string> providerSpecificPickList)
			=> null;

		public void SetProperty(string path, PSObject propertyValue)
		{
			if (propertyValue == null)
				return;

			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath) || IsHivePath(providerPath))
				throw new ArgumentException("Path must be a registry key.", nameof(path));

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				using var session = OpenRegistrySession(drive.ServerName, token);
				using var key = OpenRegistryKey(
					session.Client,
					parsed,
					RegistryAccessRights.SetValue,
					RegistryAccessRights.EnumerateSubkeys,
					token);

				var setParams = this.DynamicParameters as TboRegSetPropertyParams;
				foreach (var entry in EnumeratePropertyValues(propertyValue))
				{
					var valueName = DenormalizeValueName(entry.Key);
					var valueType = ResolveValueType(entry.Value, setParams?.Type);
					var data = EncodeValue(valueType, entry.Value);
					key.SetValue(valueName, valueType, data, token).GetAwaiter().GetResult();
				}
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
			if (IsRootPath(providerPath) || IsHivePath(providerPath))
				throw new ArgumentException("Path must be a registry key.", nameof(path));

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				using var session = OpenRegistrySession(drive.ServerName, token);
				using var key = OpenRegistryKey(
					session.Client,
					parsed,
					RegistryAccessRights.SetValue,
					RegistryAccessRights.EnumerateSubkeys,
					token);
				var valueName = DenormalizeValueName(propertyName);
				key.DeleteValue(valueName, token).GetAwaiter().GetResult();
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
			if (IsRootPath(providerPath) || IsHivePath(providerPath))
				throw new ArgumentException("Path must be a registry value.", nameof(path));

			return this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				using var session = OpenRegistrySession(drive.ServerName, token);

				if (TryGetValue(session.Client, parsed, token, out var valueInfo, out _))
					return (IContentReader)new TboRegContentReader(valueInfo);

				using var key = TryOpenKey(session.Client, parsed, RegistryAccessRights.QueryValue, token);
				if (key != null)
					throw new NotSupportedException("Get-Content requires a registry value path. Use Get-ChildItem or Get-ItemProperty for keys.");

				throw new ItemNotFoundException($"Registry value not found: {parsed.KeyPath}");
			});
		}

		public object GetContentReaderDynamicParameters(string path)
			=> null;

		public IContentWriter GetContentWriter(string path)
			=> throw new NotSupportedException("Writing registry values with Set-Content is not supported. Use Set-ItemProperty instead.");

		public object GetContentWriterDynamicParameters(string path)
			=> null;

		private static bool IsRootPath(string providerPath)
			=> string.IsNullOrWhiteSpace(providerPath) || providerPath == "\\";

		private static bool IsHivePath(string providerPath)
		{
			if (string.IsNullOrWhiteSpace(providerPath))
				return false;

			var normalized = providerPath.TrimStart('\\');
			string rootPart = normalized.Split('\\', 2)[0].TrimEnd(':');
			if (RemoteRegistryClient.TryResolveRootKey(rootPart) == RegistryRootKey.Invalid)
				return false;

			return normalized.IndexOf('\\') < 0;
		}

		private static string CombineProviderPath(string basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}

		private static string NormalizeValueName(string name)
			=> string.IsNullOrEmpty(name) ? DefaultValueName : name;

		private static string DenormalizeValueName(string name)
			=> string.Equals(name, DefaultValueName, StringComparison.OrdinalIgnoreCase) ? string.Empty : name;

		private static string NormalizeServerName(string root)
		{
			if (string.IsNullOrWhiteSpace(root))
				throw new ArgumentException("Drive root must be a server name.", nameof(root));

			var trimmed = root.Trim();
			if (trimmed.StartsWith(@"\\", StringComparison.Ordinal))
			{
				if (UncPath.TryParse(trimmed, out var unc) && unc != null)
				{
					if (!string.IsNullOrEmpty(unc.ShareName))
						throw new ArgumentException("Drive root must be a server name, not a UNC share.", nameof(root));
					return unc.ServerName;
				}

				trimmed = trimmed.TrimStart('\\');
			}

			return trimmed.TrimEnd('\\');
		}

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

			if (!hasQualifier && !hasDrivePrefix && !IsRootedRegistryPath(providerPath))
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

						providerPath = CombineProviderPath(current, providerPath);
					}
				}
			}

			return providerPath;
		}

		private static bool IsRootedRegistryPath(string providerPath)
		{
			if (string.IsNullOrWhiteSpace(providerPath))
				return false;

			var normalized = providerPath.TrimStart('\\');
			string rootPart = normalized.Split('\\', 2)[0].TrimEnd(':');
			return RemoteRegistryClient.TryResolveRootKey(rootPart) != RegistryRootKey.Invalid;
		}

		private SmbProviderInfo GetSmbProviderInfo()
			=> (SmbProviderInfo)this.SessionState.Provider.GetOne(SmbProvider.ProviderName);

		private RemoteRegistrySession OpenRegistrySession(string serverName, CancellationToken cancellationToken)
		{
			var smb = GetSmbProviderInfo();
			return smb.OpenRemoteRegistrySessionAsync(serverName, cancellationToken).GetAwaiter().GetResult();
		}

		private static RegistryKey OpenRegistryKey(
			RemoteRegistryClient client,
			RegistryPathSpec path,
			RegistryAccessRights access,
			RegistryAccessRights? rootAccess,
			CancellationToken cancellationToken)
		{
			var baseAccess = rootAccess ?? (path.IsRoot ? access : RegistryAccessRights.EnumerateSubkeys | access);
			var rootKey = client.OpenRootKey(path.RootKey, baseAccess, cancellationToken).GetAwaiter().GetResult();
			if (path.IsRoot)
				return rootKey;

			var subkeyPath = path.SubkeyPath ?? string.Empty;
			try
			{
				var key = rootKey.OpenSubkey(subkeyPath, access, BackupOptions, cancellationToken).GetAwaiter().GetResult();
				rootKey.Dispose();
				return key;
			}
			catch
			{
				rootKey.Dispose();
				throw;
			}
		}

		private static RegistryKey OpenRegistryKey(
			RemoteRegistryClient client,
			RegistryPathSpec path,
			RegistryAccessRights access,
			CancellationToken cancellationToken)
			=> OpenRegistryKey(client, path, access, null, cancellationToken);

		private static RegistryKey? TryOpenKey(
			RemoteRegistryClient client,
			RegistryPathSpec path,
			RegistryAccessRights access,
			CancellationToken cancellationToken)
		{
			try
			{
				return OpenRegistryKey(client, path, access, cancellationToken);
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME)
			{
				return null;
			}
		}

		private static IEnumerable<RegistrySubkeyInfo> EnumerateSubkeys(RegistryKey key, CancellationToken cancellationToken)
		{
			var enumerator = key.GetSubkeyNames(cancellationToken).GetAsyncEnumerator();
			try
			{
				while (enumerator.MoveNextAsync().AsTask().GetAwaiter().GetResult())
					yield return enumerator.Current;
			}
			finally
			{
				try
				{
					enumerator.DisposeAsync().AsTask().GetAwaiter().GetResult();
				}
				catch (NotSupportedException)
				{
				}
			}
		}

		private static IEnumerable<RegistryValueInfo> EnumerateValues(RegistryKey key, bool includeData, CancellationToken cancellationToken)
		{
			if (!includeData)
				return CollectValues(key, includeData: false, cancellationToken);

			try
			{
				return CollectValues(key, includeData: true, cancellationToken);
			}
			catch (NotSupportedException)
			{
				var values = CollectValues(key, includeData: false, cancellationToken);
				var fullValues = new List<RegistryValueInfo>(values.Count);
				foreach (var value in values)
					fullValues.Add(key.GetValue(value.Name, cancellationToken).GetAwaiter().GetResult());
				return fullValues;
			}
		}

		private static List<RegistryValueInfo> CollectValues(RegistryKey key, bool includeData, CancellationToken cancellationToken)
		{
			var values = new List<RegistryValueInfo>();
			var enumerator = key.GetValues(includeData, cancellationToken).GetAsyncEnumerator();
			try
			{
				while (enumerator.MoveNextAsync().AsTask().GetAwaiter().GetResult())
					values.Add(enumerator.Current);
			}
			finally
			{
				try
				{
					enumerator.DisposeAsync().AsTask().GetAwaiter().GetResult();
				}
				catch (NotSupportedException)
				{
				}
			}

			return values;
		}

		private static string[] CollectValueNames(RegistryKey key, CancellationToken cancellationToken)
		{
			var values = CollectValues(key, includeData: false, cancellationToken);
			if (values.Count == 0)
				return Array.Empty<string>();

			var names = new string[values.Count];
			for (int i = 0; i < values.Count; i++)
				names[i] = NormalizeValueName(values[i].Name);
			return names;
		}

		private static bool TryValueExists(RemoteRegistryClient client, RegistryPathSpec path, CancellationToken cancellationToken)
		{
			if (string.IsNullOrEmpty(path.SubkeyPath))
				return false;

			var parentSubkey = RegistryPath.GetParentKeyNameFromPath(path.SubkeyPath);
			var valueName = RegistryPath.GetSubkeyNameFromPath(path.SubkeyPath);
			var parentSpec = new RegistryPathSpec(path.RootKey, path.RootName, parentSubkey);

			try
			{
				using var parentKey = OpenRegistryKey(client, parentSpec, RegistryAccessRights.QueryValue, cancellationToken);
				valueName = DenormalizeValueName(valueName);
				parentKey.GetValue(valueName, cancellationToken).GetAwaiter().GetResult();
				return true;
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND)
			{
				return false;
			}
		}

		private static bool TryGetValue(RemoteRegistryClient client, RegistryPathSpec path, CancellationToken cancellationToken, out RegistryValueInfo info, out string keyPath)
		{
			info = null!;
			keyPath = string.Empty;
			if (string.IsNullOrEmpty(path.SubkeyPath))
				return false;

			var parentSubkey = RegistryPath.GetParentKeyNameFromPath(path.SubkeyPath);
			var valueName = RegistryPath.GetSubkeyNameFromPath(path.SubkeyPath);
			var parentSpec = new RegistryPathSpec(path.RootKey, path.RootName, parentSubkey);

			try
			{
				using var parentKey = OpenRegistryKey(client, parentSpec, RegistryAccessRights.QueryValue, cancellationToken);
				valueName = DenormalizeValueName(valueName);
				info = parentKey.GetValue(valueName, cancellationToken).GetAwaiter().GetResult();
				keyPath = parentSpec.KeyPath;
				return true;
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND)
			{
				return false;
			}
		}

		private static void RemoveRegistryKey(RemoteRegistryClient client, RegistryPathSpec path, bool recurse, CancellationToken cancellationToken)
		{
			if (path.IsRoot)
				throw new InvalidOperationException("Cannot remove a root registry key.");

			var subkeyPath = path.SubkeyPath!;
			var parentPath = RegistryPath.GetParentKeyNameFromPath(subkeyPath);
			var subkeyName = RegistryPath.GetSubkeyNameFromPath(subkeyPath);
			var parentSpec = new RegistryPathSpec(path.RootKey, path.RootName, parentPath);

			using var parentKey = OpenRegistryKey(
				client,
				parentSpec,
				RegistryAccessRights.CreateSubkey | RegistryAccessRights.EnumerateSubkeys,
				RegistryAccessRights.EnumerateSubkeys,
				cancellationToken);

			if (recurse)
			{
				RemoveSubkeyRecursive(parentKey, subkeyName, cancellationToken);
				return;
			}

			parentKey.DeleteSubkey(subkeyName, cancellationToken).GetAwaiter().GetResult();
		}

		private static void RemoveSubkeyRecursive(RegistryKey parentKey, string subkeyName, CancellationToken cancellationToken)
		{
			using var subkey = parentKey.OpenSubkey(
				subkeyName,
				RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.CreateSubkey,
				BackupOptions,
				cancellationToken).GetAwaiter().GetResult();

			foreach (var child in EnumerateSubkeys(subkey, cancellationToken))
			{
				RemoveSubkeyRecursive(subkey, child.KeyName, cancellationToken);
			}

			parentKey.DeleteSubkey(subkeyName, cancellationToken).GetAwaiter().GetResult();
		}

		private static void RemoveRegistryValue(RemoteRegistryClient client, RegistryPathSpec path, CancellationToken cancellationToken)
		{
			if (string.IsNullOrEmpty(path.SubkeyPath))
				throw new InvalidOperationException("Path must specify a registry value.");

			var parentSubkey = RegistryPath.GetParentKeyNameFromPath(path.SubkeyPath);
			var valueName = RegistryPath.GetSubkeyNameFromPath(path.SubkeyPath);
			var parentSpec = new RegistryPathSpec(path.RootKey, path.RootName, parentSubkey);

			using var parentKey = OpenRegistryKey(
				client,
				parentSpec,
				RegistryAccessRights.SetValue,
				RegistryAccessRights.EnumerateSubkeys,
				cancellationToken);
			valueName = DenormalizeValueName(valueName);
			parentKey.DeleteValue(valueName, cancellationToken).GetAwaiter().GetResult();
		}

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

		private static RegistryValueType ResolveValueType(object? value, RegistryValueType? type)
		{
			if (type.HasValue)
				return type.Value;

			if (value == null)
				return RegistryValueType.None;

			if (value is string)
				return RegistryValueType.String;
			if (value is string[] or IEnumerable<string>)
				return RegistryValueType.MultiString;
			if (value is byte[])
				return RegistryValueType.Binary;
			if (value is int or uint or short or ushort or byte or sbyte)
				return RegistryValueType.DwordLE;
			if (value is long or ulong)
				return RegistryValueType.Qword;

			throw new ArgumentException("Unable to infer registry value type. Specify the value type explicitly.");
		}

		private static byte[] EncodeValue(RegistryValueType valueType, object? value)
		{
			if (valueType == RegistryValueType.None)
				return Array.Empty<byte>();

			switch (valueType)
			{
				case RegistryValueType.String:
				case RegistryValueType.ExpandString:
					return EncodeString(Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty);
				case RegistryValueType.MultiString:
					return EncodeMultiString(ResolveStringList(value));
				case RegistryValueType.DwordLE:
					return EncodeUInt32(Convert.ToUInt32(value, CultureInfo.InvariantCulture), littleEndian: true);
				case RegistryValueType.DwordBE:
					return EncodeUInt32(Convert.ToUInt32(value, CultureInfo.InvariantCulture), littleEndian: false);
				case RegistryValueType.Qword:
					return EncodeUInt64(Convert.ToUInt64(value, CultureInfo.InvariantCulture));
				case RegistryValueType.Binary:
					if (value is byte[] bytes)
						return bytes;
					throw new ArgumentException("Binary registry values must be provided as a byte array.");
				default:
					throw new ArgumentException($"Unsupported registry value type: {valueType}.");
			}
		}

		private static byte[] EncodeString(string value)
		{
			return Encoding.Unicode.GetBytes(value + '\0');
		}

		private static byte[] EncodeMultiString(IReadOnlyList<string> values)
		{
			StringBuilder sb = new StringBuilder();
			foreach (var item in values)
			{
				sb.Append(item);
				sb.Append('\0');
			}

			sb.Append('\0');
			return Encoding.Unicode.GetBytes(sb.ToString());
		}

		private static IReadOnlyList<string> ResolveStringList(object? value)
		{
			if (value == null)
				throw new ArgumentException("MultiString registry values must be provided as a string array.");

			if (value is string[] array)
				return array;
			if (value is IEnumerable<string> enumerable)
				return new List<string>(enumerable);
			if (value is string single)
				return new[] { single };

			throw new ArgumentException("MultiString registry values must be provided as a string array.");
		}

		private static byte[] EncodeUInt32(uint value, bool littleEndian)
		{
			var data = BitConverter.GetBytes(value);
			if (BitConverter.IsLittleEndian != littleEndian)
				Array.Reverse(data);
			return data;
		}

		private static byte[] EncodeUInt64(ulong value)
		{
			var data = BitConverter.GetBytes(value);
			if (!BitConverter.IsLittleEndian)
				Array.Reverse(data);
			return data;
		}
	}

	internal sealed class TboRegGetChildItemParams
	{
		[Parameter]
		public SwitchParameter IncludeValues { get; set; }

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
