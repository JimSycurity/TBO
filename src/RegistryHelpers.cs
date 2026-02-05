using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Text;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;

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

	internal static class RegistryHelpers
	{
		internal const RegistryKeyOptions BackupOptions = RegistryKeyOptions.BackupRestore;
		internal const string DefaultValueName = "(Default)";

		internal static string NormalizeValueName(string name)
			=> string.IsNullOrEmpty(name) ? DefaultValueName : name;

		internal static string DenormalizeValueName(string name)
			=> string.Equals(name, DefaultValueName, StringComparison.OrdinalIgnoreCase) ? string.Empty : name;

		internal static bool IsRootPath(string providerPath)
			=> string.IsNullOrWhiteSpace(providerPath) || providerPath == "\\";

		internal static bool IsHivePath(string providerPath)
		{
			if (string.IsNullOrWhiteSpace(providerPath))
				return false;

			var normalized = providerPath.TrimStart('\\');
			string rootPart = normalized.Split('\\', 2)[0].TrimEnd(':');
			if (RemoteRegistryClient.TryResolveRootKey(rootPart) == RegistryRootKey.Invalid)
				return false;

			return normalized.IndexOf('\\') < 0;
		}

		internal static string CombineProviderPath(string basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}

		internal static string NormalizeServerName(string root)
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

		internal static bool IsRootedRegistryPath(string providerPath)
		{
			if (string.IsNullOrWhiteSpace(providerPath))
				return false;

			var normalized = providerPath.TrimStart('\\');
			string rootPart = normalized.Split('\\', 2)[0].TrimEnd(':');
			return RemoteRegistryClient.TryResolveRootKey(rootPart) != RegistryRootKey.Invalid;
		}

		internal static IRegistryKey OpenRegistryKey(
			IRegistryClient client,
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

		internal static IRegistryKey OpenRegistryKey(
			IRegistryClient client,
			RegistryPathSpec path,
			RegistryAccessRights access,
			CancellationToken cancellationToken)
			=> OpenRegistryKey(client, path, access, null, cancellationToken);

		internal static IRegistryKey? TryOpenKey(
			IRegistryClient client,
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

		internal static IEnumerable<RegistrySubkeyInfo> EnumerateSubkeys(IRegistryKey key, CancellationToken cancellationToken)
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

		internal static List<RegistrySubkeyInfo> CollectSubkeys(IRegistryKey key, CancellationToken cancellationToken)
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
				}
			}

			return subkeys;
		}

		internal static IEnumerable<RegistryValueInfo> EnumerateValues(IRegistryKey key, bool includeData, CancellationToken cancellationToken)
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

		internal static List<RegistryValueInfo> CollectValues(IRegistryKey key, bool includeData, CancellationToken cancellationToken)
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

		internal static string[] CollectValueNames(IRegistryKey key, CancellationToken cancellationToken)
		{
			var values = CollectValues(key, includeData: false, cancellationToken);
			if (values.Count == 0)
				return Array.Empty<string>();

			var names = new string[values.Count];
			for (int i = 0; i < values.Count; i++)
				names[i] = NormalizeValueName(values[i].Name);
			return names;
		}

		internal static bool TryValueExists(IRegistryClient client, RegistryPathSpec path, CancellationToken cancellationToken)
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

		internal static bool TryGetValue(
			IRegistryClient client,
			RegistryPathSpec path,
			CancellationToken cancellationToken,
			out RegistryValueInfo info,
			out string keyPath)
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

		internal static void RemoveRegistryKey(IRegistryClient client, RegistryPathSpec path, bool recurse, CancellationToken cancellationToken)
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

		internal static void RemoveRegistryValue(IRegistryClient client, RegistryPathSpec path, CancellationToken cancellationToken)
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

		internal static RegistryValueType ResolveValueType(object? value, RegistryValueType? type)
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

		internal static byte[] EncodeValue(RegistryValueType valueType, object? value)
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

		internal static IReadOnlyList<string> ResolveStringList(object? value)
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

		private static void RemoveSubkeyRecursive(IRegistryKey parentKey, string subkeyName, CancellationToken cancellationToken)
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
	}
}
