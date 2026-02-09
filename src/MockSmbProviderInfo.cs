using System;
using System.Threading;
using System.Threading.Tasks;
using Titanis.Smb2;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class MockSmbProviderInfo : ISmbProviderInfo, ISmbFileSystemProvider, IRegistrySessionProvider, IRegistrySessionInvalidator, IRegistrySecretCacheStore
	{
		public Smb2Client? SmbClient { get; set; }
		public ISmbFileSystem? FileSystem { get; set; }
		private readonly object _secretCacheLock = new();
		private readonly Dictionary<string, RegistrySecretCache> _secretCaches = new(StringComparer.OrdinalIgnoreCase);
		private SmbConnectionParameters? _defaultConnectParameters = SmbConnectionParameters.GetDefault();
		public object? DefaultConnectParameters
		{
			get => this._defaultConnectParameters;
			set
			{
				if (value is null)
					throw new ArgumentNullException(nameof(value));
				if (value is not SmbConnectionParameters parameters)
					throw new ArgumentException("DefaultConnectParameters must be a SmbConnectionParameters instance.", nameof(value));
				this._defaultConnectParameters = parameters;
			}
		}

		public Func<string, bool, object?>? GetConnectParametersForFunc { get; set; }
		public Action<string, object>? SetConnectParametersAction { get; set; }
		public Func<string, CancellationToken, Task<ServerServiceSession>>? OpenServerServiceSessionAsyncFunc { get; set; }
		public Func<string, CancellationToken, Task<RemoteRegistrySession>>? OpenRemoteRegistrySessionAsyncFunc { get; set; }
		public Func<string, CancellationToken, IRegistrySession?>? OpenRegistrySessionFunc { get; set; }
		public Action<string, RegistrySessionInvalidationReason>? InvalidateRegistrySessionAction { get; set; }
		public Action<RegistrySessionInvalidationReason>? InvalidateAllRegistrySessionsAction { get; set; }
		public Func<string, int?, bool, Task>? DisconnectServerAsyncFunc { get; set; }
		public Func<bool, Task>? DisconnectAllAsyncFunc { get; set; }
		public Action<string, Exception>? LogExceptionAction { get; set; }

		Smb2Client ISmbProviderInfo.SmbClient
			=> this.SmbClient ?? throw new InvalidOperationException("SmbClient was not configured on MockSmbProviderInfo.");

		object? ISmbProviderInfo.DefaultConnectParameters
		{
			get => this._defaultConnectParameters;
			set
			{
				if (value is null)
					throw new ArgumentNullException(nameof(value));
				if (value is not SmbConnectionParameters parameters)
					throw new ArgumentException("DefaultConnectParameters must be a SmbConnectionParameters instance.", nameof(value));
				this._defaultConnectParameters = parameters;
			}
		}

		object? ISmbProviderInfo.GetConnectParametersFor(string serverName, bool defaultIfNone)
		{
			if (this.GetConnectParametersForFunc != null)
				return this.GetConnectParametersForFunc(serverName, defaultIfNone);
			return defaultIfNone ? this._defaultConnectParameters : null;
		}

		void ISmbProviderInfo.SetConnectParameters(string serverName, object parameters)
		{
			if (this.SetConnectParametersAction == null)
				throw new InvalidOperationException("SetConnectParametersAction is not configured.");
			this.SetConnectParametersAction(serverName, parameters);
		}

		Task<ServerServiceSession> ISmbProviderInfo.OpenServerServiceSessionAsync(string serverName, CancellationToken cancellationToken)
		{
			if (this.OpenServerServiceSessionAsyncFunc == null)
				throw new InvalidOperationException("OpenServerServiceSessionAsyncFunc is not configured.");
			return this.OpenServerServiceSessionAsyncFunc(serverName, cancellationToken);
		}

		Task<RemoteRegistrySession> ISmbProviderInfo.OpenRemoteRegistrySessionAsync(string serverName, CancellationToken cancellationToken)
		{
			if (this.OpenRemoteRegistrySessionAsyncFunc == null)
				throw new InvalidOperationException("OpenRemoteRegistrySessionAsyncFunc is not configured.");
			return this.OpenRemoteRegistrySessionAsyncFunc(serverName, cancellationToken);
		}

		IRegistrySession? IRegistrySessionProvider.OpenRegistrySession(string serverName, CancellationToken cancellationToken)
			=> this.OpenRegistrySessionFunc?.Invoke(serverName, cancellationToken);

		void IRegistrySessionInvalidator.InvalidateRegistrySession(string serverName, RegistrySessionInvalidationReason reason)
			=> this.InvalidateRegistrySessionAction?.Invoke(serverName, reason);

		void IRegistrySessionInvalidator.InvalidateAllRegistrySessions(RegistrySessionInvalidationReason reason)
			=> this.InvalidateAllRegistrySessionsAction?.Invoke(reason);

		Task ISmbProviderInfo.DisconnectServerAsync(string serverName, int? port, bool force)
			=> this.DisconnectServerAsyncFunc?.Invoke(serverName, port, force) ?? Task.CompletedTask;

		Task ISmbProviderInfo.DisconnectAllAsync(bool force)
			=> this.DisconnectAllAsyncFunc?.Invoke(force) ?? Task.CompletedTask;

		void ISmbProviderInfo.LogException(string context, Exception ex)
			=> this.LogExceptionAction?.Invoke(context, ex);

		ISmbFileSystem? ISmbFileSystemProvider.FileSystem => this.FileSystem;

		RegistrySecretCache IRegistrySecretCacheStore.GetOrCreateRegistrySecretCache(string serverName)
		{
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("Server name must be provided.", nameof(serverName));

			lock (_secretCacheLock)
			{
				if (!_secretCaches.TryGetValue(serverName, out var cache))
				{
					cache = new RegistrySecretCache();
					_secretCaches.Add(serverName, cache);
				}

				return cache;
			}
		}

		// Convenience for Pester tests to pre-populate the per-connection secret cache.
		public void AddCachedDpapiMasterKey(string serverName, string masterKeyGuid, byte[] masterKey)
		{
			if (string.IsNullOrWhiteSpace(masterKeyGuid))
				throw new ArgumentException("Master key GUID must be provided.", nameof(masterKeyGuid));
			if (!Guid.TryParse(masterKeyGuid, out var guid))
				throw new ArgumentException("Master key GUID was invalid.", nameof(masterKeyGuid));

			var cache = ((IRegistrySecretCacheStore)this).GetOrCreateRegistrySecretCache(serverName);
			cache.SetDpapiMasterKey(guid, masterKey);
		}
	}
}
