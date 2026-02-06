using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class FakeRegistryStore
	{
		private sealed class Node
		{
			public Node(string keyName, string keyPath)
			{
				KeyName = keyName;
				KeyPath = keyPath;
				LastWriteTime = DateTime.UtcNow;
			}

			public string KeyName { get; }
			public string KeyPath { get; }
			public string? ClassName { get; set; }
			public DateTime LastWriteTime { get; set; }
			public byte[]? SecurityDescriptor { get; set; }
			public Dictionary<string, Node> Subkeys { get; } = new(StringComparer.OrdinalIgnoreCase);
			public Dictionary<string, FakeValue> Values { get; } = new(StringComparer.OrdinalIgnoreCase);
		}

		private sealed record FakeValue(RegistryValueType ValueType, byte[] Bytes);

		private readonly Dictionary<RegistryRootKey, Node> _roots = new();

		public FakeRegistryStore()
		{
			foreach (RegistryRootKey root in Enum.GetValues(typeof(RegistryRootKey)))
			{
				if (root == RegistryRootKey.Invalid)
					continue;
				var name = RemoteRegistryClient.GetRootName(root);
				_roots[root] = new Node(name, name);
			}
		}

		public FakeRegistryStore AddKey(string registryPath, string? className = null)
		{
			var spec = RegistryPathParser.Parse(registryPath, nameof(registryPath));
			var node = EnsureNode(spec.RootKey, spec.SubkeyPath);
			node.ClassName = className;
			node.LastWriteTime = DateTime.UtcNow;
			return this;
		}

		public FakeRegistryStore SetValue(string registryPath, string name, RegistryValueType valueType, byte[] data)
		{
			if (string.IsNullOrWhiteSpace(name))
				throw new ArgumentException("Value name must be provided.", nameof(name));

			var spec = RegistryPathParser.Parse(registryPath, nameof(registryPath));
			var node = EnsureNode(spec.RootKey, spec.SubkeyPath);
			node.Values[name] = new FakeValue(valueType, data ?? Array.Empty<byte>());
			node.LastWriteTime = DateTime.UtcNow;
			return this;
		}

		public FakeRegistryStore SetStringValue(string registryPath, string name, string value, bool expand = false)
		{
			var type = expand ? RegistryValueType.ExpandString : RegistryValueType.String;
			var bytes = Encoding.Unicode.GetBytes(value + '\0');
			return SetValue(registryPath, name, type, bytes);
		}

		public FakeRegistryStore SetMultiStringValue(string registryPath, string name, IEnumerable<string> values)
		{
			var sb = new StringBuilder();
			foreach (var item in values ?? Array.Empty<string>())
			{
				sb.Append(item);
				sb.Append('\0');
			}
			sb.Append('\0');
			return SetValue(registryPath, name, RegistryValueType.MultiString, Encoding.Unicode.GetBytes(sb.ToString()));
		}

		public FakeRegistryStore SetDwordValue(string registryPath, string name, uint value, bool bigEndian = false)
		{
			var bytes = BitConverter.GetBytes(value);
			if (BitConverter.IsLittleEndian == bigEndian)
				Array.Reverse(bytes);
			var type = bigEndian ? RegistryValueType.DwordBE : RegistryValueType.DwordLE;
			return SetValue(registryPath, name, type, bytes);
		}

		public FakeRegistryStore SetQwordValue(string registryPath, string name, ulong value)
		{
			var bytes = BitConverter.GetBytes(value);
			if (!BitConverter.IsLittleEndian)
				Array.Reverse(bytes);
			return SetValue(registryPath, name, RegistryValueType.Qword, bytes);
		}

		public FakeRegistryStore SetBinaryValue(string registryPath, string name, byte[] data)
			=> SetValue(registryPath, name, RegistryValueType.Binary, data);

		public FakeRegistryStore SetSecurityDescriptor(string registryPath, byte[] securityDescriptor)
		{
			var spec = RegistryPathParser.Parse(registryPath, nameof(registryPath));
			var node = EnsureNode(spec.RootKey, spec.SubkeyPath);
			node.SecurityDescriptor = securityDescriptor;
			return this;
		}

		private Node EnsureNode(RegistryRootKey rootKey, string? subkeyPath)
		{
			var root = _roots[rootKey];
			if (string.IsNullOrWhiteSpace(subkeyPath))
				return root;

			var parts = subkeyPath.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
			var current = root;
			foreach (var part in parts)
			{
				if (!current.Subkeys.TryGetValue(part, out var child))
				{
					var path = string.IsNullOrEmpty(current.KeyPath) ? part : $"{current.KeyPath}\\{part}";
					child = new Node(part, path);
					current.Subkeys[part] = child;
				}
				current = child;
			}

			return current;
		}

		private Node? TryGetNode(RegistryRootKey rootKey, string? subkeyPath)
		{
			if (!_roots.TryGetValue(rootKey, out var root))
				return null;
			if (string.IsNullOrWhiteSpace(subkeyPath))
				return root;

			var parts = subkeyPath.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
			var current = root;
			foreach (var part in parts)
			{
				if (!current.Subkeys.TryGetValue(part, out var child))
					return null;
				current = child;
			}

			return current;
		}

		internal static object? TryDecodeValue(RegistryValueType valueType, byte[]? data)
		{
			if (data is null)
				return null;

			return (valueType, data.Length) switch
			{
				(RegistryValueType.Qword, 8) => BinaryPrimitives.ReadUInt64LittleEndian(data),
				(RegistryValueType.DwordLE, 4) => BinaryPrimitives.ReadUInt32LittleEndian(data),
				(RegistryValueType.DwordBE, 4) => BinaryPrimitives.ReadUInt32BigEndian(data),
				(RegistryValueType.String, _) => TryDecodeUtf16String(data),
				(RegistryValueType.ExpandString, _) => TryDecodeUtf16String(data),
				(RegistryValueType.MultiString, _) => TryDecodeUtf16MultiString(data),
				_ => null
			};
		}

		private static string? TryDecodeUtf16String(byte[] bytes)
		{
			if ((bytes.Length % 2) != 0)
				return null;

			var length = bytes.Length;
			if (length >= 2 && bytes[^1] == 0 && bytes[^2] == 0)
				length -= 2;

			try
			{
				return Encoding.Unicode.GetString(bytes, 0, length);
			}
			catch
			{
				return null;
			}
		}

		private static string[]? TryDecodeUtf16MultiString(byte[] bytes)
		{
			int startIndex = 0;
			List<string> strs = new List<string>();

			for (int i = 2; i <= bytes.Length; i += 2)
			{
				var c = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(i - 2, 2));
				if (c == 0)
				{
					try
					{
						strs.Add(Encoding.Unicode.GetString(bytes.AsSpan(startIndex, i - startIndex)));
					}
					catch
					{
						return null;
					}
					startIndex = i;
				}
			}

			return strs.ToArray();
		}

		public IRegistrySession CreateSession()
			=> new FakeRegistrySession(this);

		public sealed class FakeRegistrySession : IRegistrySession, IRegistrySecretCacheProvider
		{
			private readonly FakeRegistryClient _client;
			private readonly RegistrySecretCache _secretCache = new();

			internal FakeRegistrySession(FakeRegistryStore store)
			{
				_client = new FakeRegistryClient(store ?? throw new ArgumentNullException(nameof(store)));
			}

			public IRegistryClient Client => _client;
			RegistrySecretCache IRegistrySecretCacheProvider.SecretCache => _secretCache;

			public void Dispose()
			{
			}
		}

		private sealed class FakeRegistryClient : IRegistryClient
		{
			private readonly FakeRegistryStore _store;

			internal FakeRegistryClient(FakeRegistryStore store)
			{
				_store = store;
			}

			public Task<IRegistryKey> OpenRootKey(RegistryRootKey rootKey, RegistryAccessRights access, CancellationToken cancellationToken)
			{
				var node = _store.TryGetNode(rootKey, null);
				if (node == null)
					throw new Win32Exception((int)Win32ErrorCode.ERROR_FILE_NOT_FOUND);
				return Task.FromResult<IRegistryKey>(new FakeRegistryKey(_store, node));
			}
		}

		private sealed class FakeRegistryKey : IRegistryKey
		{
			private readonly FakeRegistryStore _store;
			private readonly Node _node;

			internal FakeRegistryKey(FakeRegistryStore store, Node node)
			{
				_store = store;
				_node = node;
			}

			public string KeyName => _node.KeyName;
			public string KeyPath => _node.KeyPath;

			public Task<IRegistryKey> OpenSubkey(string subkeyPath, RegistryAccessRights access, RegistryKeyOptions options, CancellationToken cancellationToken)
			{
				var node = ResolveSubkey(subkeyPath, create: false);
				if (node == null)
					throw new Win32Exception((int)Win32ErrorCode.ERROR_FILE_NOT_FOUND);
				return Task.FromResult<IRegistryKey>(new FakeRegistryKey(_store, node));
			}

			public Task<IRegistryKey> CreateSubkey(string subkeyName, RegistryAccessRights access, RegistryKeyOptions options, CancellationToken cancellationToken)
			{
				if (string.IsNullOrWhiteSpace(subkeyName))
					throw new ArgumentException("Subkey name must be provided.", nameof(subkeyName));
				var node = ResolveSubkey(subkeyName, create: true)!;
				node.LastWriteTime = DateTime.UtcNow;
				return Task.FromResult<IRegistryKey>(new FakeRegistryKey(_store, node));
			}

			public Task DeleteSubkey(string subkeyName, CancellationToken cancellationToken)
			{
				if (!_node.Subkeys.Remove(subkeyName))
					throw new Win32Exception((int)Win32ErrorCode.ERROR_FILE_NOT_FOUND);
				_node.LastWriteTime = DateTime.UtcNow;
				return Task.CompletedTask;
			}

			public Task DeleteValue(string? name, CancellationToken cancellationToken)
			{
				var key = name ?? string.Empty;
				if (!_node.Values.Remove(key))
					throw new Win32Exception((int)Win32ErrorCode.ERROR_FILE_NOT_FOUND);
				_node.LastWriteTime = DateTime.UtcNow;
				return Task.CompletedTask;
			}

			public Task SetValue(string? name, RegistryValueType valueType, byte[] data, CancellationToken cancellationToken)
			{
				var key = name ?? string.Empty;
				_node.Values[key] = new FakeValue(valueType, data ?? Array.Empty<byte>());
				_node.LastWriteTime = DateTime.UtcNow;
				return Task.CompletedTask;
			}

			public Task<RegistryKeyInfo> QueryInfo(CancellationToken cancellationToken)
				=> QueryInfo(includeClass: true, cancellationToken);

			public Task<RegistryKeyInfo> QueryInfo(bool includeClass, CancellationToken cancellationToken)
			{
				var values = _node.Values.Values.ToArray();
				var maxValueName = _node.Values.Keys.DefaultIfEmpty(string.Empty).Max(k => k?.Length ?? 0);
				var maxValueData = values.Length == 0 ? 0 : values.Max(v => v.Bytes.Length);
				var maxSubkeyLen = _node.Subkeys.Keys.DefaultIfEmpty(string.Empty).Max(k => k?.Length ?? 0);
				var maxClassLen = _node.Subkeys.Values.DefaultIfEmpty(null).Max(k => k?.ClassName?.Length ?? 0);
				var info = new RegistryKeyInfo
				{
					ClassName = includeClass ? _node.ClassName : null,
					SubkeyCount = _node.Subkeys.Count,
					MaxSubkeyLength = maxSubkeyLen,
					MaxClassLength = maxClassLen,
					ValueCount = _node.Values.Count,
					MaxValueNameLength = maxValueName,
					MaxValueDataLength = maxValueData,
					SecurityDescriptorLength = _node.SecurityDescriptor?.Length ?? 0,
					LastWriteTime = _node.LastWriteTime
				};

				return Task.FromResult(info);
			}

			public async IAsyncEnumerable<RegistrySubkeyInfo> GetSubkeyNames(CancellationToken cancellationToken)
			{
				foreach (var kvp in _node.Subkeys.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
				{
					cancellationToken.ThrowIfCancellationRequested();
					yield return new RegistrySubkeyInfo(kvp.Key, kvp.Value.ClassName);
					await Task.Yield();
				}
			}

			public async IAsyncEnumerable<RegistryValueInfo> GetValues(bool includeData, CancellationToken cancellationToken)
			{
				foreach (var kvp in _node.Values.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
				{
					cancellationToken.ThrowIfCancellationRequested();
					var bytes = includeData ? kvp.Value.Bytes.ToArray() : null;
					yield return new RegistryValueInfo(
						kvp.Key,
						kvp.Value.ValueType,
						kvp.Value.Bytes.Length,
						bytes,
						includeData ? TryDecodeValue(kvp.Value.ValueType, kvp.Value.Bytes) : null);
					await Task.Yield();
				}
			}

			public Task<RegistryValueInfo> GetValue(string? name, CancellationToken cancellationToken)
			{
				var key = name ?? string.Empty;
				if (!_node.Values.TryGetValue(key, out var value))
					throw new Win32Exception((int)Win32ErrorCode.ERROR_FILE_NOT_FOUND);

				return Task.FromResult(new RegistryValueInfo(
					key,
					value.ValueType,
					value.Bytes.Length,
					value.Bytes.ToArray(),
					TryDecodeValue(value.ValueType, value.Bytes)));
			}

			public Task<byte[]> QuerySecurity(SecurityInfo info, CancellationToken cancellationToken)
			{
				return Task.FromResult(_node.SecurityDescriptor ?? Array.Empty<byte>());
			}

			public Task SetSecurity(SecurityInfo info, byte[] securityDescriptor, CancellationToken cancellationToken)
			{
				_node.SecurityDescriptor = securityDescriptor;
				_node.LastWriteTime = DateTime.UtcNow;
				return Task.CompletedTask;
			}

			private Node? ResolveSubkey(string subkeyPath, bool create)
			{
				if (string.IsNullOrWhiteSpace(subkeyPath))
					return _node;

				var parts = subkeyPath.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
				var current = _node;
				foreach (var part in parts)
				{
					if (!current.Subkeys.TryGetValue(part, out var child))
					{
						if (!create)
							return null;
						child = new Node(part, $"{current.KeyPath}\\{part}");
						current.Subkeys[part] = child;
					}
					current = child;
				}

				return current;
			}

			public void Dispose()
			{
			}
		}
	}
}
