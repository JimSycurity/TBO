using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class LocalRegistrySession : IRegistrySession, IRegistrySecretCacheProvider
	{
		internal static bool IsLocalServerName(string serverName)
		{
			if (string.IsNullOrWhiteSpace(serverName))
				return false;

			// For cmdlets (-ServerName) and the TBO.Reg provider (-Root), accept a small set of explicit aliases.
			// Avoid trying to resolve arbitrary hostnames/IPs here because that risks misclassifying remote hosts.
			var trimmed = serverName.Trim().TrimStart('\\').TrimEnd('\\');

			if (string.Equals(trimmed, "localhost", StringComparison.OrdinalIgnoreCase))
				return true;

			if (string.Equals(trimmed, ".", StringComparison.Ordinal))
				return true;

			// Treat the local machine name as local, so users can pass -ServerName $env:COMPUTERNAME without forcing MS-RRP.
			var machineName = Environment.MachineName;
			if (!string.IsNullOrWhiteSpace(machineName)
				&& string.Equals(trimmed, machineName, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			// Loopback IP literals.
			var ipLiteral = StripIpv6Brackets(trimmed);
			if (IPAddress.TryParse(ipLiteral, out var ip) && IPAddress.IsLoopback(ip))
				return true;

			return false;
		}

		private static string StripIpv6Brackets(string value)
		{
			if (string.IsNullOrEmpty(value))
				return value;

			// Some callers may include IPv6 literals in brackets (e.g., "[::1]"); IPAddress.TryParse does not accept brackets.
			if (value.Length >= 2 && value[0] == '[' && value[^1] == ']')
				return value.Substring(1, value.Length - 2);

			return value;
		}

		private readonly LocalRegistryClient _client;
		private readonly RegistrySecretCache _secretCache = new();

		internal LocalRegistrySession(Action<string>? logDiagnostic = null, Action<string>? logWarning = null)
		{
			_client = new LocalRegistryClient(logDiagnostic, logWarning);
		}

		public IRegistryClient Client => _client;

		RegistrySecretCache IRegistrySecretCacheProvider.SecretCache => _secretCache;

		public void Dispose()
		{
			// No session-level native resources. Keys own their handles.
		}

		private sealed class LocalRegistryClient : IRegistryClient
		{
			private readonly Action<string> _logDiagnostic;
			private readonly Action<string> _logWarning;

			internal LocalRegistryClient(Action<string>? logDiagnostic, Action<string>? logWarning)
			{
				_logDiagnostic = logDiagnostic ?? (_ => { });
				_logWarning = logWarning ?? (_ => { });
			}

			public Task<IRegistryKey> OpenRootKey(RegistryRootKey rootKey, RegistryAccessRights access, CancellationToken cancellationToken)
			{
				cancellationToken.ThrowIfCancellationRequested();

				var handle = LocalRegistryNative.OpenRootKey(rootKey, access, _logDiagnostic, _logWarning);
				var name = RemoteRegistryClient.GetRootName(rootKey);
				return Task.FromResult<IRegistryKey>(new LocalRegistryKey(handle, name, name, access, _logDiagnostic, _logWarning));
			}
		}

		private sealed class LocalRegistryKey : IRegistryKey
		{
			private readonly SafeRegistryHandle _handle;
			private readonly RegistryAccessRights _openAccess;
			private readonly Action<string> _logDiagnostic;
			private readonly Action<string> _logWarning;

			internal LocalRegistryKey(
				SafeRegistryHandle handle,
				string keyName,
				string keyPath,
				RegistryAccessRights openAccess,
				Action<string> logDiagnostic,
				Action<string> logWarning)
			{
				_handle = handle ?? throw new ArgumentNullException(nameof(handle));
				KeyName = keyName ?? throw new ArgumentNullException(nameof(keyName));
				KeyPath = keyPath ?? throw new ArgumentNullException(nameof(keyPath));
				_openAccess = openAccess;
				_logDiagnostic = logDiagnostic ?? throw new ArgumentNullException(nameof(logDiagnostic));
				_logWarning = logWarning ?? throw new ArgumentNullException(nameof(logWarning));
			}

			public string KeyName { get; }
			public string KeyPath { get; }

			public Task<IRegistryKey> OpenSubkey(string subkeyPath, RegistryAccessRights access, RegistryKeyOptions options, CancellationToken cancellationToken)
			{
				cancellationToken.ThrowIfCancellationRequested();

				var handle = LocalRegistryNative.OpenSubkey(_handle, subkeyPath, access, options, _logDiagnostic, _logWarning);
				var name = RegistryPath.GetSubkeyNameFromPath(subkeyPath);
				var path = RegistryPath.Combine(this.KeyPath, subkeyPath) ?? this.KeyPath;
				return Task.FromResult<IRegistryKey>(new LocalRegistryKey(handle, name, path, access, _logDiagnostic, _logWarning));
			}

			public Task<IRegistryKey> CreateSubkey(string subkeyName, RegistryAccessRights access, RegistryKeyOptions options, CancellationToken cancellationToken)
			{
				cancellationToken.ThrowIfCancellationRequested();

				bool createdNew;
				var handle = LocalRegistryNative.CreateSubkey(_handle, subkeyName, access, options, out createdNew, _logDiagnostic, _logWarning);
				if (createdNew)
					_logDiagnostic($"Local registry: created key '{RegistryPath.Combine(this.KeyPath, subkeyName)}'.");

				var name = RegistryPath.GetSubkeyNameFromPath(subkeyName);
				var path = RegistryPath.Combine(this.KeyPath, subkeyName) ?? this.KeyPath;
				return Task.FromResult<IRegistryKey>(new LocalRegistryKey(handle, name, path, access, _logDiagnostic, _logWarning));
			}

			public Task DeleteSubkey(string subkeyName, CancellationToken cancellationToken)
			{
				cancellationToken.ThrowIfCancellationRequested();

				LocalRegistryNative.DeleteSubkey(_handle, subkeyName, _openAccess, _logDiagnostic);
				return Task.CompletedTask;
			}

			public Task DeleteValue(string? name, CancellationToken cancellationToken)
			{
				cancellationToken.ThrowIfCancellationRequested();

				LocalRegistryNative.DeleteValue(_handle, name, _logDiagnostic);
				return Task.CompletedTask;
			}

			public Task SetValue(string? name, RegistryValueType valueType, byte[] data, CancellationToken cancellationToken)
			{
				cancellationToken.ThrowIfCancellationRequested();

				LocalRegistryNative.SetValue(_handle, name, valueType, data, _logDiagnostic);
				return Task.CompletedTask;
			}

			public Task<RegistryKeyInfo> QueryInfo(CancellationToken cancellationToken)
				=> QueryInfo(includeClass: true, cancellationToken);

			public Task<RegistryKeyInfo> QueryInfo(bool includeClass, CancellationToken cancellationToken)
			{
				cancellationToken.ThrowIfCancellationRequested();

				uint classChars = 0;
				StringBuilder? classBuffer = null;
				if (includeClass)
				{
					classChars = 256;
					classBuffer = new StringBuilder((int)classChars);
				}

				uint subkeyCount;
				uint maxSubkeyLen;
				uint maxClassLen;
				uint valueCount;
				uint maxValueNameLen;
				uint maxValueDataLen;
				uint sdLen;
				FileTime lastWriteTime;

				while (true)
				{
					uint classCharsInput = classChars;
					var res = (Win32ErrorCode)RegQueryInfoKey(
						_handle,
						classBuffer,
						ref classCharsInput,
						IntPtr.Zero,
						out subkeyCount,
						out maxSubkeyLen,
						out maxClassLen,
						out valueCount,
						out maxValueNameLen,
						out maxValueDataLen,
						out sdLen,
						out lastWriteTime);

					if (res == Win32ErrorCode.ERROR_MORE_DATA && includeClass)
					{
						// classCharsInput is the required size (chars). Expand and retry.
						classChars = Math.Max(classChars * 2, classCharsInput + 1);
						classBuffer = new StringBuilder((int)classChars);
						continue;
					}

					if (res != Win32ErrorCode.ERROR_SUCCESS)
						throw new Win32Exception((int)res, $"RegQueryInfoKey failed for '{this.KeyPath}': {res}.");

					var info = new RegistryKeyInfo
					{
						ClassName = includeClass ? classBuffer?.ToString() : null,
						SubkeyCount = (int)subkeyCount,
						MaxSubkeyLength = (int)maxSubkeyLen,
						MaxClassLength = (int)maxClassLen,
						ValueCount = (int)valueCount,
						MaxValueNameLength = (int)maxValueNameLen,
						MaxValueDataLength = (int)maxValueDataLen,
						SecurityDescriptorLength = (int)sdLen,
						LastWriteTime = lastWriteTime.ToDateTimeUtc(),
					};

					return Task.FromResult(info);
				}
			}

			public async IAsyncEnumerable<RegistrySubkeyInfo> GetSubkeyNames([EnumeratorCancellation] CancellationToken cancellationToken)
			{
				// RegEnumKeyEx only requires KEY_ENUMERATE_SUB_KEYS, while RegQueryInfoKey requires KEY_QUERY_VALUE.
				// A number of call paths intentionally omit QueryValue when only enumerating keys.
				// To avoid over-requiring rights, enumerate until NO_MORE_ITEMS without calling RegQueryInfoKey.
				uint nameChars = 256;
				uint index = 0;
				while (true)
				{
					cancellationToken.ThrowIfCancellationRequested();

					uint nameLen = nameChars;
					var name = new StringBuilder((int)nameChars);

					var res = (Win32ErrorCode)RegEnumKeyEx(
						_handle,
						index,
						name,
						ref nameLen,
						IntPtr.Zero,
						null,
						IntPtr.Zero,
						out _);

					if (res == Win32ErrorCode.ERROR_NO_MORE_ITEMS)
						yield break;

					if (res == Win32ErrorCode.ERROR_MORE_DATA)
					{
						// Retry with the required length.
						nameChars = Math.Max(nameChars * 2, nameLen + 1);
						continue;
					}

					if (res != Win32ErrorCode.ERROR_SUCCESS)
						throw new Win32Exception((int)res, $"RegEnumKeyEx failed for '{this.KeyPath}': {res}.");

					yield return new RegistrySubkeyInfo(name.ToString(), className: null);
					index++;
					await Task.Yield();
				}
			}

			public async IAsyncEnumerable<RegistryValueInfo> GetValues(bool includeData, [EnumeratorCancellation] CancellationToken cancellationToken)
			{
				var info = QueryInfo(includeClass: false, cancellationToken).GetAwaiter().GetResult();
				if (info.ValueCount == 0)
					yield break;

				uint nameChars = (uint)Math.Max(1, info.MaxValueNameLength + 1);
				uint dataBytesHint = includeData ? (uint)Math.Max(0, info.MaxValueDataLength) : 0;

				uint index = 0;
				while (true)
				{
					cancellationToken.ThrowIfCancellationRequested();

					uint nameLen = nameChars;
					var name = new StringBuilder((int)nameChars);
					uint type;

					uint dataLen = dataBytesHint;
					byte[]? data = includeData ? new byte[dataLen] : null;

					var res = (Win32ErrorCode)RegEnumValue(
						_handle,
						index,
						name,
						ref nameLen,
						IntPtr.Zero,
						out type,
						data,
						ref dataLen);

					if (res == Win32ErrorCode.ERROR_NO_MORE_ITEMS)
						yield break;

					if (res == Win32ErrorCode.ERROR_MORE_DATA)
					{
						// Name buffer too small (rare) or data buffer too small (common when includeData==false).
						if (nameLen >= nameChars)
						{
							nameChars = Math.Max(nameChars * 2, nameLen + 1);
							continue;
						}

						if (!includeData)
						{
							// We intentionally didn't provide a data buffer; treat this as success and surface length/type.
							res = Win32ErrorCode.ERROR_SUCCESS;
						}
						else
						{
							// Retry with the required data length.
							data = new byte[dataLen];
							nameLen = nameChars;
							name.Clear();
							res = (Win32ErrorCode)RegEnumValue(
								_handle,
								index,
								name,
								ref nameLen,
								IntPtr.Zero,
								out type,
								data,
								ref dataLen);
						}
					}

					if (res != Win32ErrorCode.ERROR_SUCCESS)
						throw new Win32Exception((int)res, $"RegEnumValue failed for '{this.KeyPath}': {res}.");

					byte[]? bytes = includeData ? TrimData(data, dataLen) : null;
					var valueType = (RegistryValueType)type;
					yield return new RegistryValueInfo(
						name.ToString(),
						valueType,
						(int)dataLen,
						bytes,
						includeData ? TryDecodeValue(valueType, bytes) : null);

					index++;
					await Task.Yield();
				}
			}

			public Task<RegistryValueInfo> GetValue(string? name, CancellationToken cancellationToken)
			{
				cancellationToken.ThrowIfCancellationRequested();

				string? queryName = string.IsNullOrEmpty(name) ? null : name;
				uint type;
				uint dataLen = 0;
				var res = (Win32ErrorCode)RegQueryValueEx(_handle, queryName, IntPtr.Zero, out type, null, ref dataLen);
				if (res is not Win32ErrorCode.ERROR_SUCCESS and not Win32ErrorCode.ERROR_MORE_DATA)
					throw new Win32Exception((int)res, $"RegQueryValueEx failed for '{this.KeyPath}': {res}.");

				byte[]? data = dataLen > 0 ? new byte[dataLen] : Array.Empty<byte>();
				if (dataLen > 0)
				{
					var res2 = (Win32ErrorCode)RegQueryValueEx(_handle, queryName, IntPtr.Zero, out type, data, ref dataLen);
					if (res2 != Win32ErrorCode.ERROR_SUCCESS)
						throw new Win32Exception((int)res2, $"RegQueryValueEx failed for '{this.KeyPath}': {res2}.");
				}

				var valueType = (RegistryValueType)type;
				var bytes = TrimData(data, dataLen);
				return Task.FromResult(new RegistryValueInfo(name ?? string.Empty, valueType, (int)dataLen, bytes, TryDecodeValue(valueType, bytes)));
			}

			public Task<byte[]> QuerySecurity(SecurityInfo info, CancellationToken cancellationToken)
			{
				cancellationToken.ThrowIfCancellationRequested();
				return Task.FromResult(LocalRegistryNative.QuerySecurity(_handle, info, _logDiagnostic, _logWarning));
			}

			public Task SetSecurity(SecurityInfo info, byte[] securityDescriptor, CancellationToken cancellationToken)
			{
				cancellationToken.ThrowIfCancellationRequested();
				LocalRegistryNative.SetSecurity(_handle, info, securityDescriptor, _logDiagnostic, _logWarning);
				return Task.CompletedTask;
			}

			private static byte[]? TrimData(byte[]? buffer, uint length)
			{
				if (buffer == null)
					return null;

				if (length == 0)
					return Array.Empty<byte>();

				if (length == buffer.Length)
					return buffer;

				var trimmed = new byte[length];
				Buffer.BlockCopy(buffer, 0, trimmed, 0, (int)length);
				return trimmed;
			}

			private static object? TryDecodeValue(RegistryValueType valueType, byte[]? data)
			{
				if (data is null)
					return null;

				return (valueType, data.Length) switch
				{
					(RegistryValueType.Qword, 8) => BinaryPrimitives.ReadUInt64LittleEndian(data),
					(RegistryValueType.DwordLE, 4) => BinaryPrimitives.ReadUInt32LittleEndian(data),
					(RegistryValueType.DwordBE, 4) => BinaryPrimitives.ReadUInt32BigEndian(data),
					(RegistryValueType.String, _) => TryDecodeUtf16String(data),
					(RegistryValueType.MultiString, _) => TryDecodeUtf16MultiString(data),
					(RegistryValueType.Binary, _) => null,
					_ => null
				};
			}

			private static string? TryDecodeUtf16String(byte[] bytes)
			{
				int length = bytes.Length;

				if ((length % 2) != 0)
					return null;

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
				// Match Titanis.Msrpc.Msrrp.RegistryKey.TryDecodeUtf16MultiString for output parity between local and remote.
				int startIndex = 0;
				List<string> strs = new();

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
					}
				}

				return strs.ToArray();
			}

			public void Dispose()
			{
				_handle.Dispose();
			}

			[StructLayout(LayoutKind.Sequential)]
			private struct FileTime
			{
				public uint LowDateTime;
				public uint HighDateTime;

				public DateTime ToDateTimeUtc()
				{
					long ft = ((long)HighDateTime << 32) | LowDateTime;
					if (ft <= 0)
						return DateTime.MinValue;
					return DateTime.FromFileTimeUtc(ft);
				}
			}

			[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			private static extern int RegQueryInfoKey(
				SafeRegistryHandle hKey,
				StringBuilder? lpClass,
				ref uint lpcchClass,
				IntPtr lpReserved,
				out uint lpcSubKeys,
				out uint lpcbMaxSubKeyLen,
				out uint lpcbMaxClassLen,
				out uint lpcValues,
				out uint lpcbMaxValueNameLen,
				out uint lpcbMaxValueLen,
				out uint lpcbSecurityDescriptor,
				out FileTime lpftLastWriteTime);

			[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			private static extern int RegEnumKeyEx(
				SafeRegistryHandle hKey,
				uint dwIndex,
				StringBuilder lpName,
				ref uint lpcName,
				IntPtr lpReserved,
				StringBuilder? lpClass,
				IntPtr lpcClass,
				out FileTime lpftLastWriteTime);

			[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			private static extern int RegEnumValue(
				SafeRegistryHandle hKey,
				uint dwIndex,
				StringBuilder lpValueName,
				ref uint lpcchValueName,
				IntPtr lpReserved,
				out uint lpType,
				byte[]? lpData,
				ref uint lpcbData);

			[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			private static extern int RegQueryValueEx(
				SafeRegistryHandle hKey,
				string? lpValueName,
				IntPtr lpReserved,
				out uint lpType,
				byte[]? lpData,
				ref uint lpcbData);
		}
	}
}
