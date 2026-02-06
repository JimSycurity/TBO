using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Titanis.Smb2;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProviderInfo : IRegistrySessionProvider, IRegistrySessionInvalidator
	{
		private readonly object _registrySessionLock = new();
		private readonly Dictionary<RegistrySessionKey, RegistrySessionCacheEntry> _registrySessions = new(RegistrySessionKeyComparer.Instance);

		IRegistrySession? IRegistrySessionProvider.OpenRegistrySession(string serverName, CancellationToken cancellationToken)
			=> this.GetOrCreateRegistrySession(serverName, cancellationToken);

		void IRegistrySessionInvalidator.InvalidateRegistrySession(string serverName, RegistrySessionInvalidationReason reason)
			=> this.InvalidateRegistrySessions(serverName, reason);

		void IRegistrySessionInvalidator.InvalidateAllRegistrySessions(RegistrySessionInvalidationReason reason)
			=> this.InvalidateRegistrySessions(null, reason);

		internal IRegistrySession GetOrCreateRegistrySession(string serverName, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("Server name must be provided.", nameof(serverName));

			var parms = this.GetConnectParametersFor(serverName, true);
			var port = parms?.RemotePort ?? Smb2Client.TcpPort;
			var fingerprint = BuildRegistrySessionFingerprint(parms);
			var key = new RegistrySessionKey(serverName, port, fingerprint);

			RegistrySessionCacheEntry entry;
			lock (_registrySessionLock)
			{
				if (!this._registrySessions.TryGetValue(key, out entry))
				{
					entry = new RegistrySessionCacheEntry(this, serverName, port, fingerprint);
					this._registrySessions.Add(key, entry);
				}
			}

			return entry.Acquire(cancellationToken);
		}

		private static string BuildRegistrySessionFingerprint(SmbConnectionParameters? parms)
		{
			if (parms == null)
				return string.Empty;

			var builder = new StringBuilder(256);
			AppendFingerprint(builder, parms.HostName);
			AppendFingerprint(builder, parms.RemotePort);
			AppendFingerprint(builder, parms.UserName);
			AppendFingerprint(builder, parms.UserDomain);
			AppendFingerprint(builder, parms.Password);
			AppendFingerprint(builder, parms.NtlmHash?.LmHash);
			AppendFingerprint(builder, parms.NtlmHash?.NtHash);
			AppendFingerprint(builder, parms.AesKey?.Bytes);
			AppendFingerprint(builder, parms.DesKey?.Bytes);
			AppendFingerprint(builder, parms.Tgt);
			AppendFingerprint(builder, parms.Tickets);
			AppendFingerprint(builder, parms.TicketCache);
			AppendFingerprint(builder, parms.Kdc);
			AppendFingerprint(builder, parms.KdcPort);
			AppendFingerprint(builder, parms.Workstation);
			AppendFingerprint(builder, parms.Dialects);
			AppendFingerprint(builder, parms.Capabilities?.ToString());
			AppendFingerprint(builder, parms.SecurityMode?.ToString());
			AppendFingerprint(builder, parms.RequireSecureNegotiate.IsPresent);
			AppendFingerprint(builder, parms.EnforceVersionCompliance.IsPresent);
			AppendFingerprint(builder, parms.ClientGuid);
			AppendFingerprint(builder, parms.PreauthSaltLength);
			AppendFingerprint(builder, parms.Ciphers);
			AppendFingerprint(builder, parms.SigningAlgorithms);
			AppendFingerprint(builder, parms.CompressionCapabilities?.ToString());
			AppendFingerprint(builder, parms.CompressionAlgorithms);

			var bytes = Encoding.UTF8.GetBytes(builder.ToString());
			var hash = SHA256.HashData(bytes);
			return Convert.ToHexString(hash);
		}

		private static void AppendFingerprint(StringBuilder builder, string? value)
		{
			builder.Append(value ?? string.Empty);
			builder.Append('|');
		}

		private static void AppendFingerprint(StringBuilder builder, int? value)
		{
			builder.Append(value?.ToString() ?? string.Empty);
			builder.Append('|');
		}

		private static void AppendFingerprint(StringBuilder builder, bool? value)
		{
			builder.Append(value?.ToString() ?? string.Empty);
			builder.Append('|');
		}

		private static void AppendFingerprint(StringBuilder builder, Guid? value)
		{
			builder.Append(value?.ToString() ?? string.Empty);
			builder.Append('|');
		}

		private static void AppendFingerprint<T>(StringBuilder builder, IEnumerable<T>? values)
		{
			if (values == null)
			{
				builder.Append('|');
				return;
			}

			foreach (var value in values)
			{
				builder.Append(value?.ToString() ?? string.Empty);
				builder.Append(';');
			}

			builder.Append('|');
		}

		private static void AppendFingerprint(StringBuilder builder, IEnumerable<string>? values)
		{
			if (values == null)
			{
				builder.Append('|');
				return;
			}

			foreach (var value in values)
			{
				builder.Append(value ?? string.Empty);
				builder.Append(';');
			}

			builder.Append('|');
		}

		private static void AppendFingerprint(StringBuilder builder, byte[]? bytes)
		{
			if (bytes == null || bytes.Length == 0)
			{
				builder.Append('|');
				return;
			}

			builder.Append(Convert.ToHexString(bytes));
			builder.Append('|');
		}

		private void InvalidateRegistrySessions(string? serverName, RegistrySessionInvalidationReason reason)
		{
			List<RegistrySessionCacheEntry>? toInvalidate = null;
			lock (_registrySessionLock)
			{
				foreach (var pair in _registrySessions)
				{
					if (serverName != null && !StringComparer.OrdinalIgnoreCase.Equals(pair.Key.ServerName, serverName))
						continue;

					toInvalidate ??= new List<RegistrySessionCacheEntry>();
					toInvalidate.Add(pair.Value);
				}

				if (toInvalidate != null)
				{
					foreach (var entry in toInvalidate)
						_registrySessions.Remove(new RegistrySessionKey(entry.ServerName, entry.Port, entry.Fingerprint));
				}
			}

			if (toInvalidate == null)
				return;

			foreach (var entry in toInvalidate)
				entry.Invalidate(reason);
		}

		private sealed class RegistrySessionCacheEntry
		{
			private readonly SmbProviderInfo _provider;
			private readonly string _serverName;
			private readonly RegistrySecretCache _secretCache = new();
			private readonly SemaphoreSlim _gate = new(1, 1);
			private RemoteRegistrySession? _session;
			private int _invalidated;

			internal RegistrySessionCacheEntry(SmbProviderInfo provider, string serverName, int port, string fingerprint)
			{
				this._provider = provider ?? throw new ArgumentNullException(nameof(provider));
				this._serverName = serverName ?? throw new ArgumentNullException(nameof(serverName));
				this.Port = port;
				this.Fingerprint = fingerprint ?? string.Empty;
			}

			internal int Port { get; }
			internal string Fingerprint { get; }
			internal string ServerName => this._serverName;
			internal RegistrySecretCache SecretCache => this._secretCache;

			internal IRegistrySession Acquire(CancellationToken cancellationToken)
			{
				this._gate.Wait(cancellationToken);
				try
				{
					if (Interlocked.Exchange(ref this._invalidated, 0) == 1)
						this.DisposeSession();

					if (this._session == null)
						this._session = this._provider.OpenRemoteRegistrySessionAsync(this._serverName, cancellationToken).GetAwaiter().GetResult();

					var client = new RegistryClientAdapter(this._session.Client);
					return new RegistrySessionLease(this, client);
				}
				catch
				{
					this._gate.Release();
					throw;
				}
			}

			internal void Release()
			{
				if (Volatile.Read(ref this._invalidated) == 1)
					this.DisposeSession();
				this._gate.Release();
			}

			internal void Invalidate(RegistrySessionInvalidationReason reason)
			{
				Interlocked.Exchange(ref this._invalidated, 1);
				this._secretCache.Clear();
				if (this._gate.Wait(0))
				{
					try
					{
						this.DisposeSession();
					}
					finally
					{
						this._gate.Release();
					}
				}

				this._provider.LogDiagnostic($"TBO: Invalidated cached winreg session for {this._serverName} (reason: {reason}).");
			}

			internal void DisposeSession()
			{
				var session = this._session;
				this._session = null;
				session?.Dispose();
			}
		}

		private sealed class RegistrySessionLease : IRegistrySession, IRegistrySecretCacheProvider
		{
			private RegistrySessionCacheEntry? _entry;
			private readonly IRegistryClient _client;
			private readonly RegistrySecretCache _secretCache;

			internal RegistrySessionLease(RegistrySessionCacheEntry entry, IRegistryClient client)
			{
				this._entry = entry ?? throw new ArgumentNullException(nameof(entry));
				this._client = client ?? throw new ArgumentNullException(nameof(client));
				this._secretCache = entry.SecretCache;
			}

			public IRegistryClient Client => this._client;
			public RegistrySecretCache SecretCache => this._secretCache;

			public void Dispose()
			{
				var entry = Interlocked.Exchange(ref this._entry, null);
				if (entry == null)
					return;
				entry.Release();
			}
		}

		private readonly struct RegistrySessionKey : IEquatable<RegistrySessionKey>
		{
			public RegistrySessionKey(string serverName, int port, string fingerprint)
			{
				this.ServerName = serverName ?? throw new ArgumentNullException(nameof(serverName));
				this.Port = port;
				this.Fingerprint = fingerprint ?? string.Empty;
			}

			public string ServerName { get; }
			public int Port { get; }
			public string Fingerprint { get; }

			public bool Equals(RegistrySessionKey other)
				=> this.Port == other.Port
					&& StringComparer.OrdinalIgnoreCase.Equals(this.ServerName, other.ServerName)
					&& StringComparer.Ordinal.Equals(this.Fingerprint, other.Fingerprint);

			public override bool Equals(object? obj)
				=> obj is RegistrySessionKey other && this.Equals(other);

			public override int GetHashCode()
				=> HashCode.Combine(
					StringComparer.OrdinalIgnoreCase.GetHashCode(this.ServerName),
					this.Port,
					StringComparer.Ordinal.GetHashCode(this.Fingerprint));
		}

		private sealed class RegistrySessionKeyComparer : IEqualityComparer<RegistrySessionKey>
		{
			public static readonly RegistrySessionKeyComparer Instance = new();

			public bool Equals(RegistrySessionKey x, RegistrySessionKey y)
				=> x.Equals(y);

			public int GetHashCode(RegistrySessionKey obj)
				=> obj.GetHashCode();
		}
	}
}
