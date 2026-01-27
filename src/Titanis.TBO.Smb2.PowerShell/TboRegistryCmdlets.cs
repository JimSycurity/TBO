using System;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public readonly struct RegistryPathSpec
	{
		internal RegistryPathSpec(RegistryRootKey rootKey, string rootName, string? subkeyPath)
		{
			this.RootKey = rootKey;
			this.RootName = rootName;
			this.SubkeyPath = subkeyPath;
		}

		public RegistryRootKey RootKey { get; }
		public string RootName { get; }
		public string? SubkeyPath { get; }
		public bool IsRoot => string.IsNullOrEmpty(this.SubkeyPath);
		public string KeyPath => this.IsRoot ? this.RootName : $"{this.RootName}\\{this.SubkeyPath}";
	}

	internal static class RegistryPathParser
	{
		internal static RegistryPathSpec Parse(string path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Registry path must be provided.", paramName);

			var normalized = path.Trim().Replace('/', '\\');
			if (normalized.StartsWith(@"\\", StringComparison.Ordinal))
				throw new ArgumentException($"Registry path must start with a root key (for example HKLM), not a UNC path: {path}", paramName);

			int sepIndex = normalized.IndexOf('\\');
			string rootPart = sepIndex >= 0 ? normalized.Substring(0, sepIndex) : normalized;
			string? subkeyPath = sepIndex >= 0 ? normalized.Substring(sepIndex + 1) : null;

			rootPart = rootPart.TrimEnd(':');
			if (string.IsNullOrWhiteSpace(rootPart))
				throw new ArgumentException($"Registry path is missing a root key: {path}", paramName);

			var rootKey = RemoteRegistryClient.TryResolveRootKey(rootPart);
			if (rootKey == RegistryRootKey.Invalid)
				throw new ArgumentException($"Unsupported registry root key '{rootPart}'.", paramName);

			if (string.IsNullOrWhiteSpace(subkeyPath))
				subkeyPath = null;

			return new RegistryPathSpec(rootKey, RemoteRegistryClient.GetRootName(rootKey), subkeyPath);
		}
	}

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
		private const RegistryKeyOptions BackupOptions = RegistryKeyOptions.BackupRestore;

		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(SmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			this.ProcessRecord(smb, this._cancelSource.Token);
		}

		protected abstract void ProcessRecord(SmbProviderInfo smb, CancellationToken cancellationToken);

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		protected RemoteRegistrySession OpenRegistrySession(SmbProviderInfo smb, CancellationToken cancellationToken)
		{
			return smb.OpenRemoteRegistrySessionAsync(this.ServerName, cancellationToken).GetAwaiter().GetResult();
		}

		protected static RegistryPathSpec ParseRegistryPath(string path, string paramName)
		{
			return RegistryPathParser.Parse(path, paramName);
		}

		protected RegistryKey OpenRegistryKey(
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

		protected RegistryKey OpenRegistryKey(
			RemoteRegistryClient client,
			RegistryPathSpec path,
			RegistryAccessRights access,
			CancellationToken cancellationToken)
			=> OpenRegistryKey(client, path, access, null, cancellationToken);

		protected static List<RegistrySubkeyInfo> CollectSubkeys(RegistryKey key, CancellationToken cancellationToken)
		{
			var subkeys = new List<RegistrySubkeyInfo>();
			var enumerator = key.GetSubkeyNames(cancellationToken).GetAsyncEnumerator();
			try
			{
				while (enumerator.MoveNextAsync().AsTask().GetAwaiter().GetResult())
				{
					subkeys.Add(enumerator.Current);
				}
			}
			finally
			{
				try
				{
					enumerator.DisposeAsync().AsTask().GetAwaiter().GetResult();
				}
				catch (NotSupportedException)
				{
					// Some async-iterator DisposeAsync implementations throw when forced sync.
				}
			}

			return subkeys;
		}

		protected static List<RegistryValueInfo> CollectValues(RegistryKey key, bool includeData, CancellationToken cancellationToken)
		{
			var values = new List<RegistryValueInfo>();
			var enumerator = key.GetValues(includeData, cancellationToken).GetAsyncEnumerator();
			try
			{
				while (enumerator.MoveNextAsync().AsTask().GetAwaiter().GetResult())
				{
					values.Add(enumerator.Current);
				}
			}
			finally
			{
				try
				{
					enumerator.DisposeAsync().AsTask().GetAwaiter().GetResult();
				}
				catch (NotSupportedException)
				{
					// Some async-iterator DisposeAsync implementations throw when forced sync.
				}
			}

			return values;
		}
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

		protected override void ProcessRecord(SmbProviderInfo smb, CancellationToken cancellationToken)
		{
			if (this.ResolveSid.IsPresent)
				throw new NotSupportedException("ResolveSid is not implemented yet.");

			using var session = OpenRegistrySession(smb, cancellationToken);
			using var rootKey = session.Client.OpenRootKey(RegistryRootKey.Users, RegistryAccessRights.EnumerateSubkeys, cancellationToken).GetAwaiter().GetResult();

			List<RegistrySubkeyInfo> subkeys;
			try
			{
				subkeys = CollectSubkeys(rootKey, cancellationToken);
			}
			catch (Exception ex)
			{
				smb.LogException("Get-TBORegSessions failed to enumerate HKEY_USERS", ex);
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

		protected override void ProcessRecord(SmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
			using var session = OpenRegistrySession(smb, cancellationToken);
			using var key = OpenRegistryKey(
				session.Client,
				parsedPath,
				RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys,
				cancellationToken);

			var info = key.QueryInfo(this.IncludeClass.IsPresent, cancellationToken).GetAwaiter().GetResult();
			this.WriteObject(new TboRegistryKeyInfo(this.ServerName, parsedPath.KeyPath, info));
		}
	}

	[Cmdlet(VerbsCommon.New, "TBORegKey", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.Medium)]
	public sealed class NewTBORegKey : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

	protected override void ProcessRecord(SmbProviderInfo smb, CancellationToken cancellationToken)
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

			using var session = OpenRegistrySession(smb, cancellationToken);
			using var parentKey = OpenRegistryKey(
				session.Client,
				parentSpec,
				RegistryAccessRights.CreateSubkey,
				RegistryAccessRights.EnumerateSubkeys,
				cancellationToken);

			var createAccess = RegistryAccessRights.CreateSubkey | RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys;
			using var created = parentKey.CreateSubkey(subkeyName, createAccess, RegistryKeyOptions.BackupRestore, cancellationToken).GetAwaiter().GetResult();
			this.WriteObject(new TboRegistryKeyInfo(this.ServerName, parsedPath.KeyPath, created.QueryInfo(cancellationToken).GetAwaiter().GetResult()));
		}
	}

	[Cmdlet(VerbsCommon.Remove, "TBORegKey", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class RemoveTBORegKey : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

	protected override void ProcessRecord(SmbProviderInfo smb, CancellationToken cancellationToken)
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

			using var session = OpenRegistrySession(smb, cancellationToken);
			using var parentKey = OpenRegistryKey(
				session.Client,
				parentSpec,
				RegistryAccessRights.CreateSubkey,
				RegistryAccessRights.EnumerateSubkeys,
				cancellationToken);

			parentKey.DeleteSubkey(subkeyName, cancellationToken).GetAwaiter().GetResult();
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

		protected override void ProcessRecord(SmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
			using var session = OpenRegistrySession(smb, cancellationToken);
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
				smb.LogException("Get-TBORegValue failed to enumerate values with data", ex);
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
				smb.LogException("Get-TBORegValue failed to enumerate values", ex);
				throw;
			}

			foreach (var valueInfo in values)
			{
				this.WriteObject(new TboRegistryValueInfo(this.ServerName, parsedPath.KeyPath, valueInfo));
			}
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

		protected override void ProcessRecord(SmbProviderInfo smb, CancellationToken cancellationToken)
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
			using var session = OpenRegistrySession(smb, cancellationToken);
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
					smb.LogException("Get-TBORegChildItem failed to enumerate subkeys", ex);
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
					smb.LogException("Get-TBORegChildItem failed to enumerate values with data", ex);
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
					smb.LogException("Get-TBORegChildItem failed to enumerate values", ex);
					throw;
				}

				foreach (var valueInfo in values)
				{
					this.WriteObject(new TboRegistryValueInfo(this.ServerName, parsedPath.KeyPath, valueInfo));
				}
			}
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

	protected override void ProcessRecord(SmbProviderInfo smb, CancellationToken cancellationToken)
	{
		var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
		var valueType = ResolveValueType(this.Value, this.Type);
		var data = EncodeValue(valueType, this.Value);

		var target = $"{this.ServerName}\\{parsedPath.KeyPath}\\{this.Name}";
		if (!this.ShouldProcess(target, "Set registry value"))
			return;

		using var session = OpenRegistrySession(smb, cancellationToken);
		using var key = OpenRegistryKey(
			session.Client,
			parsedPath,
				RegistryAccessRights.SetValue,
				RegistryAccessRights.EnumerateSubkeys,
				cancellationToken);

			key.SetValue(this.Name, valueType, data, cancellationToken).GetAwaiter().GetResult();
		}

		private static RegistryValueType ResolveValueType(object value, RegistryValueType? type)
		{
			if (type.HasValue)
				return type.Value;

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

			throw new ArgumentException("Unable to infer registry value type. Specify -Type explicitly.");
		}

		private static byte[] EncodeValue(RegistryValueType valueType, object value)
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

		private static IReadOnlyList<string> ResolveStringList(object value)
		{
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

	[Cmdlet(VerbsCommon.Remove, "TBORegValue", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class RemoveTBORegValue : TboRegCmdlet
	{
		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 2, ValueFromPipelineByPropertyName = true)]
		public string? Name { get; set; }

	protected override void ProcessRecord(SmbProviderInfo smb, CancellationToken cancellationToken)
	{
		var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
		var target = $"{this.ServerName}\\{parsedPath.KeyPath}\\{this.Name}";
		if (!this.ShouldProcess(target, "Remove registry value"))
			return;

		using var session = OpenRegistrySession(smb, cancellationToken);
		using var key = OpenRegistryKey(
			session.Client,
			parsedPath,
				RegistryAccessRights.SetValue,
				RegistryAccessRights.EnumerateSubkeys,
				cancellationToken);

			key.DeleteValue(this.Name, cancellationToken).GetAwaiter().GetResult();
		}
	}
}
