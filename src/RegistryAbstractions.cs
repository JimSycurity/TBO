using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public interface IRegistrySession : IDisposable
	{
		IRegistryClient Client { get; }
	}

	public interface IRegistryClient
	{
		Task<IRegistryKey> OpenRootKey(RegistryRootKey rootKey, RegistryAccessRights access, CancellationToken cancellationToken);
	}

	public interface IRegistryKey : IDisposable
	{
		string KeyName { get; }
		string KeyPath { get; }

		Task<IRegistryKey> OpenSubkey(string subkeyPath, RegistryAccessRights access, RegistryKeyOptions options, CancellationToken cancellationToken);
		Task<IRegistryKey> CreateSubkey(string subkeyName, RegistryAccessRights access, RegistryKeyOptions options, CancellationToken cancellationToken);
		Task DeleteSubkey(string subkeyName, CancellationToken cancellationToken);
		Task DeleteValue(string? name, CancellationToken cancellationToken);
		Task SetValue(string? name, RegistryValueType valueType, byte[] data, CancellationToken cancellationToken);

		Task<RegistryKeyInfo> QueryInfo(CancellationToken cancellationToken);
		Task<RegistryKeyInfo> QueryInfo(bool includeClass, CancellationToken cancellationToken);
		IAsyncEnumerable<RegistrySubkeyInfo> GetSubkeyNames(CancellationToken cancellationToken);
		IAsyncEnumerable<RegistryValueInfo> GetValues(bool includeData, CancellationToken cancellationToken);
		Task<RegistryValueInfo> GetValue(string? name, CancellationToken cancellationToken);

		Task<byte[]> QuerySecurity(SecurityInfo info, CancellationToken cancellationToken);
		Task SetSecurity(SecurityInfo info, byte[] securityDescriptor, CancellationToken cancellationToken);
	}

	internal interface IRegistrySessionProvider
	{
		IRegistrySession? OpenRegistrySession(string serverName, CancellationToken cancellationToken);
	}

	internal sealed class RegistrySessionAdapter : IRegistrySession
	{
		private readonly RemoteRegistrySession _session;
		private readonly IRegistryClient _client;

		internal RegistrySessionAdapter(RemoteRegistrySession session)
		{
			_session = session ?? throw new ArgumentNullException(nameof(session));
			_client = new RegistryClientAdapter(session.Client);
		}

		public IRegistryClient Client => _client;

		public void Dispose()
		{
			_session.Dispose();
		}
	}

	internal sealed class RegistryClientAdapter : IRegistryClient
	{
		private readonly RemoteRegistryClient _client;

		internal RegistryClientAdapter(RemoteRegistryClient client)
		{
			_client = client ?? throw new ArgumentNullException(nameof(client));
		}

		public async Task<IRegistryKey> OpenRootKey(RegistryRootKey rootKey, RegistryAccessRights access, CancellationToken cancellationToken)
		{
			var key = await _client.OpenRootKey(rootKey, access, cancellationToken).ConfigureAwait(false);
			return new RegistryKeyAdapter(key);
		}
	}

	internal sealed class RegistryKeyAdapter : IRegistryKey
	{
		private readonly Titanis.Msrpc.Msrrp.RegistryKey _key;

		internal RegistryKeyAdapter(Titanis.Msrpc.Msrrp.RegistryKey key)
		{
			_key = key ?? throw new ArgumentNullException(nameof(key));
		}

		public string KeyName => _key.KeyName;
		public string KeyPath => _key.KeyPath;

		public async Task<IRegistryKey> OpenSubkey(string subkeyPath, RegistryAccessRights access, RegistryKeyOptions options, CancellationToken cancellationToken)
		{
			var key = await _key.OpenSubkey(subkeyPath, access, options, cancellationToken).ConfigureAwait(false);
			return new RegistryKeyAdapter(key);
		}

		public async Task<IRegistryKey> CreateSubkey(string subkeyName, RegistryAccessRights access, RegistryKeyOptions options, CancellationToken cancellationToken)
		{
			var key = await _key.CreateSubkey(subkeyName, access, options, cancellationToken).ConfigureAwait(false);
			return new RegistryKeyAdapter(key);
		}

		public Task DeleteSubkey(string subkeyName, CancellationToken cancellationToken)
			=> _key.DeleteSubkey(subkeyName, cancellationToken);

		public Task DeleteValue(string? name, CancellationToken cancellationToken)
			=> _key.DeleteValue(name, cancellationToken);

		public Task SetValue(string? name, RegistryValueType valueType, byte[] data, CancellationToken cancellationToken)
			=> _key.SetValue(name, valueType, data, cancellationToken);

		public Task<RegistryKeyInfo> QueryInfo(CancellationToken cancellationToken)
			=> _key.QueryInfo(cancellationToken);

		public Task<RegistryKeyInfo> QueryInfo(bool includeClass, CancellationToken cancellationToken)
			=> _key.QueryInfo(includeClass, cancellationToken);

		public IAsyncEnumerable<RegistrySubkeyInfo> GetSubkeyNames(CancellationToken cancellationToken)
			=> _key.GetSubkeyNames(cancellationToken);

		public IAsyncEnumerable<RegistryValueInfo> GetValues(bool includeData, CancellationToken cancellationToken)
			=> _key.GetValues(includeData, cancellationToken);

		public Task<RegistryValueInfo> GetValue(string? name, CancellationToken cancellationToken)
			=> _key.GetValue(name, cancellationToken);

		public Task<byte[]> QuerySecurity(SecurityInfo info, CancellationToken cancellationToken)
			=> _key.QuerySecurity(info, cancellationToken);

		public Task SetSecurity(SecurityInfo info, byte[] securityDescriptor, CancellationToken cancellationToken)
			=> _key.SetSecurity(info, securityDescriptor, cancellationToken);

		public void Dispose()
		{
			_key.Dispose();
		}
	}
}
